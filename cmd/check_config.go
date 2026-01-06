package cmd

import (
	"github.com/nerdneilsfield/seulogin/internal/configs"
	"github.com/spf13/cobra"
)

func newCheckConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "check",
		Short:        "Check the config file",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := configs.CheckConfig(args[0])
			return err
		},
	}
}
