// Package oidc implements the Vault OIDC browser login flow natively: it asks
// Vault for an auth URL, opens the browser, runs a localhost callback listener,
// and exchanges the returned code for a Vault token.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	callbackHost = "127.0.0.1:8250"
	callbackPath = "/oidc/callback"
	redirectURI  = "http://localhost:8250/oidc/callback"
)

// LaunchFunc is called with the auth URL so the caller can show/open it.
type LaunchFunc func(authURL string)

// Login performs the full OIDC flow and returns the resulting auth secret
// (which carries the client token). It blocks until the browser callback
// completes, ctx is cancelled, or the timeout elapses.
func Login(ctx context.Context, client *api.Client, mount, role string, launch LaunchFunc) (*api.Secret, error) {
	authURLData := map[string]any{
		"redirect_uri": redirectURI,
	}
	if role != "" {
		authURLData["role"] = role
	}

	sec, err := client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/oidc/auth_url", mount), authURLData)
	if err != nil {
		return nil, fmt.Errorf("requesting auth URL: %w", err)
	}
	if sec == nil || sec.Data["auth_url"] == nil || sec.Data["auth_url"] == "" {
		return nil, errors.New("vault returned no auth_url (check OIDC mount and role)")
	}
	authURL, _ := sec.Data["auth_url"].(string)

	listener, err := net.Listen("tcp", callbackHost)
	if err != nil {
		return nil, fmt.Errorf("binding %s (another login in progress?): %w", callbackHost, err)
	}
	defer listener.Close()

	type result struct {
		params map[string][]string
		err    error
	}
	resCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code") == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			resCh <- result{err: errors.New("callback missing code parameter")}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, callbackHTML)
		resCh <- result{params: q}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer srv.Close()

	if launch != nil {
		launch(authURL)
	}
	openBrowser(authURL)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, errors.New("OIDC login timed out after 5 minutes")
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		cbData := map[string][]string{
			"code":  res.params["code"],
			"state": res.params["state"],
		}
		if v := res.params["id_token"]; len(v) > 0 {
			cbData["id_token"] = v
		}
		token, err := client.Logical().ReadWithDataWithContext(ctx, fmt.Sprintf("auth/%s/oidc/callback", mount), cbData)
		if err != nil {
			return nil, fmt.Errorf("exchanging code for token: %w", err)
		}
		if token == nil || token.Auth == nil {
			return nil, errors.New("vault callback returned no auth token")
		}
		return token, nil
	}
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, url)
	_ = exec.Command(cmd, args...).Start()
}

const callbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>VaultSign</title>
<style>body{font-family:sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center}</style>
</head><body><div><h2>Authentication complete</h2>
<p>You can close this tab and return to VaultSign.</p></div></body></html>`
