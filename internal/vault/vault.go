// Package vault wraps Vault/OpenBao operations using the native Go API client
// (no `vault` CLI subprocess) and the native ssh-agent client.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"

	"github.com/dem0n1337/vaultsign/internal/config"
	"github.com/dem0n1337/vaultsign/internal/oidc"
	"github.com/dem0n1337/vaultsign/internal/sshagent"
)

// StepFunc is invoked after each step of the auth flow.
type StepFunc func(step string, ok bool, detail string)

// Backend performs Vault operations for a given profile.
type Backend struct {
	profile config.Profile
	client  *api.Client
	// LaunchOIDC, if set, is called with the OIDC auth URL when login starts.
	LaunchOIDC oidc.LaunchFunc
	// Passphrase supplies the SSH key passphrase if the key is encrypted.
	Passphrase string
	// ForceLogin skips token reuse and always runs the OIDC browser flow.
	ForceLogin bool
}

// New builds a Backend and its Vault API client from a profile.
func New(profile config.Profile) (*Backend, error) {
	cfg := api.DefaultConfig()
	cfg.Address = strings.TrimRight(profile.VaultAddr, "/")
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if tok := readTokenHelper(); tok != "" {
		client.SetToken(tok)
	}
	return &Backend{profile: profile, client: client}, nil
}

func (b *Backend) mount() string {
	if b.profile.OIDCMount != "" {
		return b.profile.OIDCMount
	}
	return "oidc"
}

func (b *Backend) signerPath() string {
	if b.profile.SSHSignerPath != "" {
		return b.profile.SSHSignerPath
	}
	return "ssh-client-signer"
}

// CheckPrerequisites verifies the SSH key pair exists and fixes loose perms.
func (b *Backend) CheckPrerequisites(cb StepFunc) (bool, string) {
	var msgs []string
	ok := true

	key := expand(b.profile.SSHKeyPath)
	pub := key + ".pub"

	if fi, err := os.Stat(key); err == nil {
		msgs = append(msgs, "SSH private key found: "+key)
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			msgs = append(msgs, fmt.Sprintf("WARNING: key perms too open (%o), fixing to 0600", mode))
			if err := os.Chmod(key, 0o600); err != nil {
				msgs = append(msgs, "could not fix perms: "+err.Error())
				ok = false
			}
		}
	} else {
		msgs = append(msgs, "SSH private key NOT found: "+key)
		ok = false
	}

	if _, err := os.Stat(pub); err == nil {
		msgs = append(msgs, "SSH public key found: "+pub)
	} else {
		msgs = append(msgs, "SSH public key NOT found: "+pub)
		ok = false
	}

	out := strings.Join(msgs, "\n")
	report(cb, "check_prerequisites", ok, out)
	return ok, out
}

// Reachable does a fast health probe so we fail clearly when the VPN is down
// instead of after launching the browser. Returns (ok, message).
func (b *Backend) Reachable(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := b.client.Sys().HealthWithContext(ctx)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "no such host") || strings.Contains(msg, "dial tcp") || strings.Contains(msg, "connection refused") {
			return false, "Vault unreachable at " + b.client.Address() + " — is the corporate VPN connected?"
		}
		return false, "Vault unreachable: " + msg
	}
	return true, "Vault reachable: " + b.client.Address()
}

// HasValidToken reports whether the current token covers the profile role,
// letting the caller skip a redundant login.
func (b *Backend) HasValidToken(ctx context.Context) bool {
	if b.client.Token() == "" {
		return false
	}
	sec, err := b.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || sec == nil {
		return false
	}
	ttl, err := sec.TokenTTL()
	return err == nil && ttl > time.Minute
}

// Login runs the OIDC browser flow and persists the resulting token.
func (b *Backend) Login(ctx context.Context, cb StepFunc) (bool, string) {
	sec, err := oidc.Login(ctx, b.client, b.mount(), b.profile.Role, b.LaunchOIDC)
	if err != nil {
		out := mapAuthError(err)
		report(cb, "vault_login", false, out)
		return false, out
	}
	token := sec.Auth.ClientToken
	b.client.SetToken(token)
	_ = writeTokenHelper(token)

	policies := strings.Join(sec.Auth.Policies, ", ")
	out := fmt.Sprintf("Authenticated. policies=[%s] ttl=%ds", policies, sec.Auth.LeaseDuration)
	report(cb, "vault_login", true, out)
	return true, out
}

// SignSSHKey signs the public key via Vault and writes <key>-cert.pub.
func (b *Backend) SignSSHKey(ctx context.Context, cb StepFunc) (bool, string) {
	key := expand(b.profile.SSHKeyPath)
	pubPath := key + ".pub"
	certPath := key + "-cert.pub"

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		out := "cannot read public key: " + err.Error()
		report(cb, "sign_ssh_key", false, out)
		return false, out
	}

	path := fmt.Sprintf("%s/sign/%s", b.signerPath(), b.profile.Role)
	sec, err := b.client.Logical().WriteWithContext(ctx, path, map[string]any{
		"public_key": string(pubBytes),
	})
	if err != nil {
		out := mapSignError(err, b.profile.Role)
		report(cb, "sign_ssh_key", false, out)
		return false, out
	}
	signed, _ := sec.Data["signed_key"].(string)
	if signed == "" {
		out := "Vault returned an empty signed key"
		report(cb, "sign_ssh_key", false, out)
		return false, out
	}
	if err := os.WriteFile(certPath, []byte(signed+"\n"), 0o600); err != nil {
		out := "cannot write certificate: " + err.Error()
		report(cb, "sign_ssh_key", false, out)
		return false, out
	}
	out := "Certificate written to " + certPath
	report(cb, "sign_ssh_key", true, out)
	return true, out
}

// AddToAgent loads the key and certificate into ssh-agent natively.
func (b *Backend) AddToAgent(cb StepFunc) (bool, string) {
	key := expand(b.profile.SSHKeyPath)
	cert := key + "-cert.pub"
	err := sshagent.AddKey(key, cert, b.Passphrase)
	if errors.Is(err, sshagent.ErrPassphrase) {
		report(cb, "add_to_ssh_agent", false, "key is passphrase-protected; supply a passphrase")
		return false, "key is passphrase-protected; supply a passphrase"
	}
	if err != nil {
		report(cb, "add_to_ssh_agent", false, err.Error())
		return false, err.Error()
	}
	out := "Key and certificate added to ssh-agent"
	report(cb, "add_to_ssh_agent", true, out)
	return true, out
}

// CertificateDetails returns a human-readable summary of the signed cert,
// replacing the ssh-keygen -L subprocess.
func (b *Backend) CertificateDetails(cb StepFunc) (bool, string) {
	key := expand(b.profile.SSHKeyPath)
	data, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		report(cb, "get_certificate_details", false, err.Error())
		return false, err.Error()
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		report(cb, "get_certificate_details", false, err.Error())
		return false, err.Error()
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		report(cb, "get_certificate_details", false, "not a certificate")
		return false, "not a certificate"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Key ID: %s\n", cert.KeyId)
	fmt.Fprintf(&sb, "Serial: %d\n", cert.Serial)
	fmt.Fprintf(&sb, "Principals: %s\n", strings.Join(cert.ValidPrincipals, ", "))
	fmt.Fprintf(&sb, "Valid from: %s\n", time.Unix(int64(cert.ValidAfter), 0).Format(time.RFC3339))
	if cert.ValidBefore == ssh.CertTimeInfinity {
		sb.WriteString("Valid to: forever\n")
	} else {
		fmt.Fprintf(&sb, "Valid to: %s\n", time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
	}
	exts := make([]string, 0, len(cert.Permissions.Extensions))
	for k := range cert.Permissions.Extensions {
		exts = append(exts, k)
	}
	sort.Strings(exts)
	fmt.Fprintf(&sb, "Extensions: %s", strings.Join(exts, ", "))
	out := sb.String()
	report(cb, "get_certificate_details", true, out)
	return true, out
}

// CertInfo is the structured form of the signed SSH certificate.
type CertInfo struct {
	Valid       bool
	KeyID       string
	Serial      uint64
	Principals  []string
	ValidAfter  time.Time
	ValidBefore time.Time
	Extensions  []string
}

// CertInfo parses the signed certificate file into structured fields, or
// returns a zero value with Valid=false if absent/unreadable.
func (b *Backend) CertInfo() CertInfo {
	key := expand(b.profile.SSHKeyPath)
	data, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		return CertInfo{}
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return CertInfo{}
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return CertInfo{}
	}
	exts := make([]string, 0, len(cert.Permissions.Extensions))
	for k := range cert.Permissions.Extensions {
		exts = append(exts, k)
	}
	sort.Strings(exts)
	info := CertInfo{
		Valid:      true,
		KeyID:      cert.KeyId,
		Serial:     cert.Serial,
		Principals: cert.ValidPrincipals,
		ValidAfter: time.Unix(int64(cert.ValidAfter), 0),
		Extensions: exts,
	}
	if cert.ValidBefore != ssh.CertTimeInfinity {
		info.ValidBefore = time.Unix(int64(cert.ValidBefore), 0)
	}
	return info
}

// TokenInfo summarizes the current token.
type TokenInfo struct {
	DisplayName string
	TTL         time.Duration
	CreationTTL time.Duration
	Policies    []string
	Renewable   bool
}

// TokenStatus returns info on the current token, or nil if none/invalid.
func (b *Backend) TokenStatus(ctx context.Context) *TokenInfo {
	if b.client.Token() == "" {
		return nil
	}
	sec, err := b.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || sec == nil {
		return nil
	}
	info := &TokenInfo{}
	info.DisplayName, _ = sec.Data["display_name"].(string)
	if ttl, err := sec.TokenTTL(); err == nil {
		info.TTL = ttl
	}
	if ct, ok := sec.Data["creation_ttl"].(json.Number); ok {
		if secs, err := ct.Int64(); err == nil {
			info.CreationTTL = time.Duration(secs) * time.Second
		}
	}
	info.Policies, _ = sec.TokenPolicies()
	info.Renewable, _ = sec.TokenIsRenewable()
	return info
}

// ListRoles returns the OIDC roles configured in Vault.
func (b *Backend) ListRoles(ctx context.Context) ([]string, error) {
	sec, err := b.client.Logical().ListWithContext(ctx, fmt.Sprintf("auth/%s/role", b.mount()))
	if err != nil || sec == nil {
		return nil, err
	}
	raw, ok := sec.Data["keys"].([]any)
	if !ok {
		return nil, nil
	}
	roles := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles, nil
}

// RenewToken renews the current token.
func (b *Backend) RenewToken(ctx context.Context) (bool, string) {
	sec, err := b.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Token renewed, ttl=%ds", sec.Auth.LeaseDuration)
}

// RunFull executes the full auth flow, stopping at the first failure.
func (b *Backend) RunFull(ctx context.Context, cb StepFunc) (bool, string) {
	if ok, out := b.CheckPrerequisites(cb); !ok {
		return false, out
	}
	if ok, out := b.Reachable(ctx); !ok {
		report(cb, "vault_login", false, out)
		return false, out
	}
	if b.ForceLogin || !b.HasValidToken(ctx) {
		if ok, out := b.Login(ctx, cb); !ok {
			return false, out
		}
	} else {
		report(cb, "vault_login", true, "Reusing existing valid token")
	}
	if ok, out := b.SignSSHKey(ctx, cb); !ok {
		return false, out
	}
	if ok, out := b.AddToAgent(cb); !ok {
		return false, out
	}
	return b.CertificateDetails(cb)
}

// --- helpers ---

func mapAuthError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "does not match any associated bound claim"):
		return "OIDC claim mismatch: your identity is not allowed for this role " +
			"(bound claim check failed). Check the role's bound_claims and your account.\n" + msg
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "dial tcp"):
		return "Cannot reach Vault — is the corporate VPN connected?\n" + msg
	case strings.Contains(msg, "Timed out waiting for response"):
		return "OIDC login timed out — browser flow not completed in time.\n" + msg
	default:
		return msg
	}
}

func mapSignError(err error, role string) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no keys configured"):
		return fmt.Sprintf("Signing role %q has no signer key configured in Vault.\n%s", role, msg)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "Code: 403"):
		return fmt.Sprintf("Permission denied signing with role %q — your token's policies may not allow it.\n%s", role, msg)
	case strings.Contains(msg, "unknown role"), strings.Contains(msg, "Code: 400"):
		return fmt.Sprintf("Vault rejected signing role %q (does it exist?).\n%s", role, msg)
	default:
		return msg
	}
}

func report(cb StepFunc, step string, ok bool, detail string) {
	if cb != nil {
		cb(step, ok, detail)
	}
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func tokenHelperPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vault-token")
}

func readTokenHelper() string {
	p := tokenHelperPath()
	if p == "" {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeTokenHelper(token string) error {
	p := tokenHelperPath()
	if p == "" {
		return nil
	}
	return os.WriteFile(p, []byte(token), 0o600)
}
