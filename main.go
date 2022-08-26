package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/team-xquare/auth/pkg/cli"

	"github.com/spf13/cobra"
)

func main() {
	root := cli.Defaults(&cobra.Command{
		Use:   "auth",
		Short: "Authentication server for the Envoy proxy",
	})

	root.AddCommand(cli.Defaults(cli.NewAuthServerCommand()))

	if err := root.Execute(); err != nil {
		if msg := err.Error(); msg != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", msg)
		}

		var exit *cli.ExitError
		if errors.As(err, &exit) {
			os.Exit(int(exit.Code))
		}

		os.Exit(int(cli.EX_FAIL))
	}
}
