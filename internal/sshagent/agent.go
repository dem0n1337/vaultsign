// Package sshagent talks to the running ssh-agent natively over its unix
// socket, removing the dependency on the ssh-add binary and the class of
// "Could not open a connection to your authentication agent" failures that
// plagued the subprocess-based implementation.
package sshagent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrPassphrase indicates the private key is encrypted and needs a passphrase.
var ErrPassphrase = errors.New("ssh private key is passphrase-protected")

// FindSocket resolves a usable ssh-agent socket, fixing the original bug where
// `systemctl --user start ssh-agent` succeeded but SSH_AUTH_SOCK was never set.
// Resolution order: live $SSH_AUTH_SOCK, systemd user agent socket (starting it
// if needed), then GNOME Keyring's gcr socket.
func FindSocket() (string, error) {
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" && connectable(s) {
		return s, nil
	}

	uid := os.Getuid()
	runDir := filepath.Join("/run/user", strconv.Itoa(uid))
	systemd := filepath.Join(runDir, "ssh-agent.socket")

	if connectable(systemd) {
		return systemd, nil
	}
	// Ask systemd to start the user ssh-agent, then use its socket.
	_ = exec.Command("systemctl", "--user", "start", "ssh-agent").Run()
	if connectable(systemd) {
		return systemd, nil
	}
	// Fall back to GNOME Keyring's gcr agent if present.
	gcr := filepath.Join(runDir, "gcr", "ssh")
	if connectable(gcr) {
		return gcr, nil
	}
	return "", errors.New("no reachable ssh-agent socket (tried SSH_AUTH_SOCK, systemd ssh-agent, gcr)")
}

func connectable(path string) bool {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func dial() (agent.ExtendedAgent, net.Conn, error) {
	sock, err := FindSocket()
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("connect %s: %w", sock, err)
	}
	return agent.NewClient(conn), conn, nil
}

// AddKey loads the private key (and its signed certificate, if present) into the
// agent. passphrase may be empty for unencrypted keys.
func AddKey(privKeyPath, certPath, passphrase string) error {
	expanded := expand(privKeyPath)
	pemBytes, err := os.ReadFile(expanded)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}

	var priv any
	if passphrase != "" {
		priv, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		priv, err = ssh.ParseRawPrivateKey(pemBytes)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return ErrPassphrase
		}
	}
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	added := agent.AddedKey{PrivateKey: priv, Comment: expanded}

	if cert := loadCert(certPath); cert != nil {
		added.Certificate = cert
	}

	client, conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	return client.Add(added)
}

func loadCert(certPath string) *ssh.Certificate {
	data, err := os.ReadFile(expand(certPath))
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil
	}
	return cert
}

// Key describes a key currently loaded in the agent.
type Key struct {
	Format      string
	Fingerprint string
	Comment     string
}

// ListKeys returns the keys currently loaded in the agent.
func ListKeys() ([]Key, error) {
	client, conn, err := dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	keys, err := client.List()
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		fp := ""
		if err == nil {
			fp = ssh.FingerprintSHA256(pub)
		}
		out = append(out, Key{Format: k.Format, Fingerprint: fp, Comment: k.Comment})
	}
	return out, nil
}

// RemoveKey removes a loaded key matching the given comment or fingerprint.
func RemoveKey(comment, fingerprint string) error {
	client, conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	keys, err := client.List()
	if err != nil {
		return err
	}
	for _, k := range keys {
		pub, perr := ssh.ParsePublicKey(k.Blob)
		match := false
		if comment != "" && k.Comment == comment {
			match = true
		}
		if perr == nil && fingerprint != "" && ssh.FingerprintSHA256(pub) == fingerprint {
			match = true
		}
		if match && perr == nil {
			return client.Remove(pub)
		}
	}
	return errors.New("key not found in agent")
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
