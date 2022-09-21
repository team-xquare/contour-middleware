package main

import (
	"log"
	"os"

	"github.com/getsentry/sentry-go"
	"github.com/spf13/cobra"
	"github.com/team-xquare/contour-middleware/pkg/cli"
)

func main() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              os.Getenv("SENTRY_DSN"),
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("error: %s\n", err)
		os.Exit(int(cli.EX_FAIL))
	}

	root := cli.Defaults(&cobra.Command{
		Use:   "auth",
		Short: "Authentication server for the Envoy proxy",
	})

	root.AddCommand(cli.Defaults(cli.NewAuthServerCommand()))

	if err := root.Execute(); err != nil {
		log.Fatalf("error: %s\n", err)
		os.Exit(int(cli.EX_FAIL))
	}
}
