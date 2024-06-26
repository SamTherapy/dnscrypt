package main

import (
	"os"

	"dns.froth.zone/dnscrypt"
	"github.com/AdguardTeam/golibs/log"
	"gopkg.in/yaml.v3"
)

// GenerateArgs is the "generate" command arguments structure
type GenerateArgs struct {
	ProviderName   string `short:"p" long:"provider-name" description:"DNSCrypt provider name. Param is required." required:"true"`
	Out            string `short:"o" long:"out" description:"Path to the resulting config file. Param is required." required:"true"`
	PrivateKey     string `short:"k" long:"private-key" description:"Private key (hex-encoded)"`
	CertificateTTL int    `short:"t" long:"ttl" description:"Certificate time-to-live (seconds)"`
}

// generate generates a DNSCrypt server configuration
func generate(args GenerateArgs) {
	log.Info("Generating configuration for %s", args.ProviderName)

	var privateKey []byte
	var err error
	if args.PrivateKey != "" {
		privateKey, err = dnscrypt.HexDecodeKey(args.PrivateKey)
		if err != nil {
			log.Fatalf("failed to generate private key: %v", err)
		}
	}

	rc, err := dnscrypt.GenerateResolverConfig(args.ProviderName, privateKey)
	if err != nil {
		log.Fatalf("failed to generate resolver config: %v", err)
	}

	b, err := yaml.Marshal(rc)
	if err != nil {
		log.Fatalf("failed to serialize to yaml: %v", err)
	}

	// nolint
	err = os.WriteFile(args.Out, b, 0600)
	if err != nil {
		log.Fatalf("failed to save %s: %v", args.Out, err)
	}

	log.Info("Configuration has been written to %s", args.Out)
	log.Info("Go to https://dnscrypt.info/stamps to generate an SDNS stamp")
	log.Info("You can run a DNSCrypt server using the following command:")
	log.Info("dnscrypt server -c %s -f 8.8.8.8", args.Out)
}
