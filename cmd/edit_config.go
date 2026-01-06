package cmd

import (
	"github.com/nerdneilsfield/seulogin/internal/configs"
	"github.com/spf13/cobra"
)

func newEditConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "edit",
		Short:        "Edit the config file with system default editor",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := configs.EditConfigFile(args[0])
			return err
		},
	}
}
