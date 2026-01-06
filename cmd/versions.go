package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd(version string, buildTime string, gitCommit string) *cobra.Command {
	return &cobra.Command{
		Use:          "version",
		Short:        "seulogin version",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			slogan := `
_____ _    _ _      ____   _____ _____ _   _ 
/ ____| |  | | |    / __ \ / ____|_   _| \ | |
| (___ | |__| | |   | |  | | |  __  | | |  \| |
\___ \|  __  | |   | |  | | | |_ | | | | . \ |
____) | |  | | |___| |__| | |__| |_| |_| |\  |
|_____/|_|  |_|______\____/ \_____|_____|_| \_|
				`
			fmt.Fprintln(cmd.OutOrStdout(), slogan)
			fmt.Fprintln(cmd.OutOrStdout(), "Author: dengqi935@gmail.com")
			fmt.Fprintln(cmd.OutOrStdout(), "Github: https://github.com/nerdneilsfield/seulogin")
			fmt.Fprintln(cmd.OutOrStdout(), "Wiki: https://nerdneilsfield.github.io/seulogin/")
			fmt.Fprintf(cmd.OutOrStdout(), "seulogin: %s\n", version)
			fmt.Fprintf(cmd.OutOrStdout(), "buildTime: %s\n", buildTime)
			fmt.Fprintf(cmd.OutOrStdout(), "gitCommit: %s\n", gitCommit)
			fmt.Fprintf(cmd.OutOrStdout(), "goVersion: %s\n", runtime.Version())
		},
	}
}
