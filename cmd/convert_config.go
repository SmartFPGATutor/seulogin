package cmd

import (
	"github.com/nerdneilsfield/seulogin/internal/configs"
	"github.com/spf13/cobra"
)

func newConvertConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "convert",
		Short:        "Convert config file: toml to json or json to toml",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return configs.ConvertConfig(args[0], args[1])
		},
	}
}
