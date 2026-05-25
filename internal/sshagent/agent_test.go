package sshagent

import (
	"os"
	"strings"
	"testing"
)

// TestFindSocketResolves checks that socket discovery either returns a
// connectable socket or a clear, actionable error — never the old silent
// "started but SSH_AUTH_SOCK unset" state that caused ssh-add to fail.
func TestFindSocketResolves(t *testing.T) {
	sock, err := FindSocket()
	if err != nil {
		if !strings.Contains(err.Error(), "no reachable ssh-agent") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if sock == "" {
		t.Fatal("FindSocket returned empty socket with nil error")
	}
	if !connectable(sock) {
		t.Fatalf("FindSocket returned non-connectable socket: %s", sock)
	}
}

func TestExpand(t *testing.T) {
	home, _ := os.UserHomeDir()
	if got := expand("~/.ssh/id_ed25519"); got != home+"/.ssh/id_ed25519" {
		t.Errorf("expand(~) = %q", got)
	}
	if got := expand("/abs/path"); got != "/abs/path" {
		t.Errorf("expand(abs) = %q", got)
	}
}
