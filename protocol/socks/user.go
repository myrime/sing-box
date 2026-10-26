package socks

import (
	"github.com/sagernet/sing/common/auth"
)

func (h *Inbound) UpdateUsers(users []auth.User) error {
	h.authenticator = auth.NewAuthenticator(users)
	// Drop all shared-UDP client registrations: existing entries may
	// reference users that were just removed. Active clients will
	// re-register transparently on their next UDP ASSOCIATE.
	if h.clients != nil {
		h.clients.purge()
	}
	return nil
}
