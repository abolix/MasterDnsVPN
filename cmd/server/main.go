// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	UDPServer "masterdnsvpn-go/internal/udpserver"
)

func main() {
	cfg, err := config.LoadServerConfig("server_config.toml")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server startup failed: %v\n", err)
		os.Exit(1)
	}

	log := logger.New("MasterDnsVPN Server", cfg.LogLevel)
	log.Infof("\U0001F680 <magenta>MasterDnsVPN Server starting ...</magenta>")

	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		log.Errorf("❌ <red>Encryption Key Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		log.Errorf("❌ <red>Encryption Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	srv := UDPServer.New(cfg, log, codec)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Infof("\U0001F680 <green>Server Configuration Loaded</green>")
	if len(cfg.Domain) > 0 {
		log.Infof(
			"\U0001F310 <green>Allowed Domains: <cyan>%s</cyan>, Min Label:<cyan>%d</cyan></green>",
			strings.Join(cfg.Domain, ", "),
			cfg.MinVPNLabelLength,
		)
	} else {
		log.Errorf(
			"⚠️ <yellow>No Allowed Domains Configured!</yellow>",
		)
		fmt.Print("Press Enter to exit...")
		_, _ = fmt.Scanln()
		os.Exit(1)
	}

	log.Infof(
		"🔐 <green>Encryption Method: <cyan>%s</cyan> <gray>(id=%d)</gray></green>",
		keyInfo.MethodName,
		keyInfo.MethodID,
	)

	if keyInfo.Generated {
		log.Warnf(
			"🗝️ <yellow>Encryption Key Generated, Path: <cyan>%s</cyan></yellow>",
			keyInfo.Path,
		)
	} else {
		log.Infof(
			"\U0001F5C2 <green>Encryption Key Loaded, Path: <cyan>%s</cyan></green>",
			keyInfo.Path,
		)
	}

	log.Infof("🔑 <green>Active Encryption Key: <yellow>%s</yellow></green>", keyInfo.Key)
	log.Debugf("▶️ <green>Starting UDP Server...</green>")

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("💥 <red>Server Stopped Unexpectedly, <cyan>%v</cyan></red>", err)
		os.Exit(1)
	}

	log.Infof("🛑 <yellow>Server Stopped</yellow>")
}
