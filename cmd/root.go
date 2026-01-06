package cmd

import (
	"fmt"

	loggerPkg "github.com/SmartFPGATutor/seulogin/pkg/logger"
	"github.com/spf13/cobra"
)

var verbose bool
var logger = loggerPkg.GetLogger()

func newRootCmd(version string, buildTime string, gitCommit string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seulogin",
		Short: "seulogin is a tool to login to the Southeast University network",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if verbose {
				logger.SetVerbose(true)
			} else {
				logger.SetVerbose(false)
			}
			logger.Reset()
		},
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	cmd.AddCommand(newVersionCmd(version, buildTime, gitCommit))
	cmd.AddCommand(newGenConfigCmd())
	cmd.AddCommand(newCheckConfigCmd())
	cmd.AddCommand(newConvertConfigCmd())
	cmd.AddCommand(newEditConfigCmd())
	cmd.AddCommand(newConnectionCmd())
	cmd.AddCommand(newLoginCmd())
	cmd.AddCommand(newCronCmd())
	cmd.AddCommand(newTuiCmd())
	return cmd
}

func Execute(version string, buildTime string, gitCommit string) error {
	if err := newRootCmd(version, buildTime, gitCommit).Execute(); err != nil {
		return fmt.Errorf("error executing root command: %w", err)
	}

	return nil
}
