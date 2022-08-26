package cli

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/team-xquare/auth/pkg/auth"
)

func NewAuthServerCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "run [OPTIONS]",
		Short: "Run a authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			listener, err := net.Listen("tcp", mustString(cmd.Flags().GetString("address")))
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, auth.NewCheckService(logrus.New()))

			logrus.Info("started serving", "address", mustString(cmd.Flags().GetString("address")))
			return auth.RunServer(listener, srv)
		},
	}

	cmd.Flags().String("address", ":9443", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "/tls/tls.crt", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "/tls/ca.crt", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "/tls/tls.key", "Path to the TLS server key.")

	return &cmd
}
