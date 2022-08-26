package cli

import (
	"fmt"
	"os"

	"github.com/team-xquare/contour-middleware/pkg/auth"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func mustString(s string, err error) string {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(int(EX_CONFIG))
	}

	return s
}

func Defaults(c *cobra.Command) *cobra.Command {
	c.SilenceUsage = true
	c.SilenceErrors = true
	c.DisableFlagsInUseLine = true

	return c
}

func DefaultServer(cmd *cobra.Command) (*grpc.Server, error) {
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(1 << 20),
	}

	creds, err := auth.NewServerCredentials(
		mustString(cmd.Flags().GetString("tls-cert-path")),
		mustString(cmd.Flags().GetString("tls-key-path")),
		mustString(cmd.Flags().GetString("tls-ca-path")),
	)
	if err != nil {
		return nil, err
	}

	opts = append(opts, grpc.Creds(creds))
	return grpc.NewServer(opts...), nil
}
