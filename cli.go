package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dem0n1337/vaultsign/internal/config"
	"github.com/dem0n1337/vaultsign/internal/logf"
	"github.com/dem0n1337/vaultsign/internal/vault"
)

// runCLI handles the headless subcommands; with no subcommand the GUI runs.
func runCLI(args []string) {
	switch args[0] {
	case "auth":
		os.Exit(cliAuth(args[1:]))
	case "status":
		os.Exit(cliStatus(args[1:]))
	case "version", "--version", "-v":
		fmt.Println("vaultsign", version)
	case "help", "--help", "-h":
		cliUsage()
	default:
		cliUsage()
		os.Exit(2)
	}
}

func cliUsage() {
	fmt.Print(`vaultsign ` + version + `

Usage:
  vaultsign              Launch the GUI
  vaultsign auth         Run the full OIDC auth + SSH signing flow (headless)
  vaultsign status       Show current Vault token status
  vaultsign version      Print version

Flags for auth/status:
  --profile NAME   Use a specific config profile
  --role NAME      Override the OIDC/signing role
`)
}

func cliProfile(args []string) config.Profile {
	fs := flag.NewFlagSet("vaultsign", flag.ExitOnError)
	profileName := fs.String("profile", "", "config profile name")
	role := fs.String("role", "", "override role")
	_ = fs.Parse(args)

	cfg := config.Load()
	if *profileName != "" {
		cfg.ActiveProfile = *profileName
	}
	p := cfg.Active()
	if *role != "" {
		p.Role = *role
	}
	return p
}

func cliAuth(args []string) int {
	p := cliProfile(args)
	log, err := logf.New()
	if err == nil {
		defer log.Close()
	}
	be, err := vault.New(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	be.LaunchOIDC = func(url string) {
		fmt.Printf("\nComplete login in your browser:\n\n    %s\n\nWaiting for OIDC callback...\n", url)
	}
	cb := func(step string, ok bool, detail string) {
		status := "FAILED"
		if ok {
			status = "OK"
		}
		fmt.Printf("[%s] %s\n", step, status)
		if detail != "" {
			fmt.Println("   ", detail)
		}
		if log != nil {
			log.Step(step, ok, detail)
		}
	}
	ok, out := be.RunFull(context.Background(), cb)
	if !ok {
		_ = config.AppendHistory("auth_failed", p.Role, "", out)
		fmt.Fprintln(os.Stderr, "\nAuth failed:", out)
		return 1
	}
	_ = config.AppendHistory("auth_success", p.Role, "", "")
	fmt.Println("\nDone.")
	return 0
}

func cliStatus(args []string) int {
	p := cliProfile(args)
	be, err := vault.New(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	info := be.TokenStatus(context.Background())
	if info == nil {
		fmt.Println("No valid Vault token.")
		return 1
	}
	fmt.Printf("Token:     %s\n", info.DisplayName)
	fmt.Printf("TTL:       %s\n", info.TTL)
	fmt.Printf("Renewable: %t\n", info.Renewable)
	fmt.Printf("Policies:  %v\n", info.Policies)
	return 0
}
