package cmd

import (
	"fmt"

	"github.com/nerdneilsfield/seulogin/internal/configs"
	"github.com/spf13/cobra"
)

func newGenConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "gen",
		Short:        "Generate an example config file: toml or json",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configType := "toml"
			if len(args) > 0 {
				configType = configs.DetectConfigType(args[0])
			}
			switch configType {
			case ".toml":
				return configs.GenDefaultConfigToml(args[0])
			case ".json":
				return configs.GenDefaultConfigJson(args[0])
			default:
				return fmt.Errorf("invalid config type: %s", configType)
			}
		},
	}
}
