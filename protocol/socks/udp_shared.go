package socks

// udp_shared.go implements the shared-socket UDP relay model for the socks
// inbound, mirroring Xray's behavior: a single UDP socket bound to the
// inbound's own listen port serves all UDP ASSOCIATE clients, instead of
// sing's default per-associate ephemeral sockets on random ports.
//
// How it works:
//
//  1. The listener binds both TCP and UDP on the same listen port.
//  2. On socks5 UDP ASSOCIATE (custom handshake, see newSharedConnection),
//     the server registers the client's source IP -> authenticated user
//     and replies BND.ADDR:BND.PORT = <tcp local addr>:<shared udp port>.
//     The TCP connection is then held open until the client closes it or
//     the entry expires, per RFC 1928.
//  3. Inbound UDP packets are attributed to a user by source IP lookup
//     against the registry, the socks5 UDP request header
//     (RSV/FRAG/ATYP/DST.ADDR/DST.PORT) is stripped, and the payload is
//     dispatched through a udpnat2 NAT session (one session per client
//     source address, same as the direct inbound).
//  4. Outbound packets are written back to the client's source address
//     with the socks5 UDP response header prepended.
//
// Trade-offs compared to the default (exclusive socket) model:
//
//   - Only the single listen port needs to be reachable over UDP.
//   - User attribution for UDP is by source IP (NAT: the most recent
//     associate wins), not per-connection, same as Xray's udp filter.
//   - SOCKS5 UDP fragmentation (FRAG != 0) is dropped, same as Xray.

import (
	std_bufio "bufio"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

const (
	// udpClientTTL is how long a registry entry survives without any
	// traffic from its client (refreshed by both UDP packets and data
	// on the associate TCP connection).
	udpClientTTL = 15 * time.Minute
	// udpClientHoldCheck is the read deadline used while holding the
	// associate TCP connection, to periodically re-check expiry.
	udpClientHoldCheck = time.Minute
)

type udpUserData struct {
	user string
}

type udpClientEntry struct {
	user     string
	lastSeen atomic.Int64
}

func (e *udpClientEntry) touch() {
	e.lastSeen.Store(time.Now().UnixNano())
}

func (e *udpClientEntry) expired(ttl time.Duration) bool {
	last := e.lastSeen.Load()
	return last == 0 || time.Since(time.Unix(0, last)) > ttl
}

type udpClientRegistry struct {
	access  sync.RWMutex
	clients map[netip.Addr]*udpClientEntry
}

func newUDPClientRegistry() *udpClientRegistry {
	return &udpClientRegistry{clients: map[netip.Addr]*udpClientEntry{}}
}

func (r *udpClientRegistry) register(addr netip.Addr, user string) *udpClientEntry {
	entry := &udpClientEntry{user: user}
	entry.touch()
	r.access.Lock()
	r.clients[addr] = entry
	r.access.Unlock()
	return entry
}

func (r *udpClientRegistry) unregister(addr netip.Addr, entry *udpClientEntry) {
	r.access.Lock()
	if current, loaded := r.clients[addr]; loaded && current == entry {
		delete(r.clients, addr)
	}
	r.access.Unlock()
}

func (r *udpClientRegistry) lookup(addr netip.Addr, ttl time.Duration) (string, bool) {
	r.access.RLock()
	entry, loaded := r.clients[addr]
	r.access.RUnlock()
	if !loaded {
		return "", false
	}
	if entry.expired(ttl) {
		return "", false
	}
	entry.touch()
	return entry.user, true
}

func (r *udpClientRegistry) purge() {
	r.access.Lock()
	r.clients = map[netip.Addr]*udpClientEntry{}
	r.access.Unlock()
}

// newSharedConnection is the socks5 handshake used when udp_shared is
// enabled. It is a re-implementation of sing's socks.HandleConnectionEx
// with the UDP ASSOCIATE branch replaced: instead of listening on a
// random ephemeral port, the associate is registered in the client
// registry and the shared listener port is returned.
func (h *Inbound) newSharedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	reader := std_bufio.NewReader(conn)
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version == socks4.Version {
		// socks4 has no UDP ASSOCIATE; defer to the standard handler.
		err = reader.UnreadByte()
		if err != nil {
			return err
		}
		return socks.HandleConnectionEx(ctx, conn, reader, h.authenticator, adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection), h.listener, h.udpTimeout, metadata.Source, onClose)
	}
	if version != socks5.Version {
		return E.New("socks: unsupported version ", version)
	}
	var authRequest socks5.AuthRequest
	authRequest, err = socks5.ReadAuthRequest0(reader)
	if err != nil {
		return err
	}
	var authMethod byte
	if h.authenticator != nil && !common.Contains(authRequest.Methods, socks5.AuthTypeUsernamePassword) {
		err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{
			Method: socks5.AuthTypeNoAcceptedMethods,
		})
		if err != nil {
			return err
		}
	}
	if h.authenticator != nil {
		authMethod = socks5.AuthTypeUsernamePassword
	} else {
		authMethod = socks5.AuthTypeNotRequired
	}
	err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{
		Method: authMethod,
	})
	if err != nil {
		return err
	}
	if authMethod == socks5.AuthTypeUsernamePassword {
		var usernamePasswordAuthRequest socks5.UsernamePasswordAuthRequest
		usernamePasswordAuthRequest, err = socks5.ReadUsernamePasswordAuthRequest(reader)
		if err != nil {
			return err
		}
		ctx = auth.ContextWithUser(ctx, usernamePasswordAuthRequest.Username)
		response := socks5.UsernamePasswordAuthResponse{}
		if h.authenticator.Verify(usernamePasswordAuthRequest.Username, usernamePasswordAuthRequest.Password) {
			response.Status = socks5.UsernamePasswordStatusSuccess
		} else {
			response.Status = socks5.UsernamePasswordStatusFailure
		}
		err = socks5.WriteUsernamePasswordAuthResponse(conn, response)
		if err != nil {
			return err
		}
		if response.Status != socks5.UsernamePasswordStatusSuccess {
			return E.New("socks5: authentication failed, username=", usernamePasswordAuthRequest.Username)
		}
	}
	var request socks5.Request
	request, err = socks5.ReadRequest(reader)
	if err != nil {
		return err
	}
	switch request.Command {
	case socks5.CommandConnect:
		adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection).
			NewConnectionEx(ctx, socks.NewLazyConn(conn, socks5.Version), metadata.Source, request.Destination, onClose)
		return nil
	case socks5.CommandUDPAssociate:
		return h.udpAssociate(ctx, conn, metadata, onClose)
	default:
		err = socks5.WriteResponse(conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeUnsupported,
		})
		if err != nil {
			return err
		}
		return E.New("socks5: unsupported command ", request.Command)
	}
}

// udpAssociate registers the client and holds the TCP connection open
// (per RFC 1928, the UDP relay ends when the TCP connection closes).
func (h *Inbound) udpAssociate(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	udpAddr := h.listener.UDPAddr()
	if udpAddr.Port == 0 {
		return E.New("socks5: udp listener is not started")
	}
	user, _ := auth.UserFromContext[string](ctx)
	entry := h.clients.register(metadata.Source.Addr, user)
	defer h.clients.unregister(metadata.Source.Addr, entry)
	bindAddr := M.Socksaddr{Addr: M.SocksaddrFromNet(conn.LocalAddr()).Unwrap().Addr, Port: udpAddr.Port}
	err := socks5.WriteResponse(conn, socks5.Response{
		ReplyCode: socks5.ReplyCodeSuccess,
		Bind:      bindAddr,
	})
	if err != nil {
		return E.Cause(err, "socks5: write response")
	}
	h.logger.DebugContext(ctx, "socks udp shared associate from ", metadata.Source, " bind ", bindAddr)
	h.holdAssociateConn(conn, entry)
	return nil
}

// holdAssociateConn blocks until the client closes the associate TCP
// connection, it errors out, or the registry entry expires.
func (h *Inbound) holdAssociateConn(conn net.Conn, entry *udpClientEntry) {
	defer conn.Close()
	var buffer [512]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpClientHoldCheck))
		_, err := conn.Read(buffer[:])
		if err == nil {
			entry.touch()
			continue
		}
		if netErr, isNetErr := err.(net.Error); isNetErr && netErr.Timeout() {
			if entry.expired(udpClientTTL) {
				return
			}
			continue
		}
		return
	}
}

// NewPacketEx implements adapter.PacketHandlerEx: called by the listener
// for every inbound UDP packet on the shared socket.
func (h *Inbound) NewPacketEx(buffer *buf.Buffer, source M.Socksaddr) {
	user, loaded := h.clients.lookup(source.Addr, udpClientTTL)
	if !loaded {
		h.logger.Debug("dropped socks udp packet from unassociated source ", source)
		return
	}
	if buffer.Len() < 3 {
		h.logger.Debug("dropped short socks udp packet from ", source)
		return
	}
	data := buffer.Bytes()
	if data[2] != 0 {
		h.logger.Debug("dropped fragmented socks udp packet from ", source)
		return
	}
	buffer.Advance(3)
	destination, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		h.logger.Debug("dropped invalid socks udp packet from ", source)
		return
	}
	h.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, destination, udpUserData{user: user})
}

// preparePacketConnection implements udpnat2.PrepareFunc.
func (h *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	var user string
	if data, ok := userData.(udpUserData); ok {
		user = data.user
	} else if looked, loaded := h.clients.lookup(source.Addr, udpClientTTL); loaded {
		user = looked
	} else {
		return false, nil, nil, nil
	}
	ctx := log.ContextWithNewID(h.ctx)
	if user != "" {
		ctx = auth.ContextWithUser(ctx, user)
	}
	return true, ctx, &sharedUDPPacketWriter{writer: h.listener.PacketWriter(), source: source}, nil
}

// NewPacketConnectionEx implements N.UDPConnectionHandlerEx: called by
// the udpnat service when a new per-source session is established.
func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination
	user, loaded := auth.UserFromContext[string](ctx)
	if loaded && user != "" {
		metadata.User = user
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// sharedUDPPacketWriter prepends the socks5 UDP response header to
// outbound packets and sends them back to the client's source address.
type sharedUDPPacketWriter struct {
	writer N.PacketWriter
	source M.Socksaddr
}

func (w *sharedUDPPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	// Rebuild the packet in a fresh buffer instead of relying on
	// front headroom of the inbound buffer: buffers coming from the
	// outbound UDP socket have no reserved headroom.
	newBuffer := buf.NewSize(3 + M.SocksaddrSerializer.AddrPortLen(destination) + buffer.Len())
	err := newBuffer.WriteZeroN(3)
	if err == nil {
		err = M.SocksaddrSerializer.WriteAddrPort(newBuffer, destination)
	}
	if err == nil {
		_, err = newBuffer.Write(buffer.Bytes())
	}
	buffer.Release()
	if err != nil {
		newBuffer.Release()
		return err
	}
	return w.writer.WritePacket(newBuffer, w.source)
}
