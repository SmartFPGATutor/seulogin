package cmd

import (
	"fmt"

	"github.com/SmartFPGATutor/seulogin/pkg/network"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newConnectionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "conn",
		Short:        "Check the connection",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := network.CheckWanConnection()
			if err != nil {
				return err
			}
			fmt.Println("Wan connection check success")
			return nil
		},
	}

	cmd.AddCommand(newHttpConnectCmd())
	cmd.AddCommand(newCheckLoginServerCmd())
	cmd.AddCommand(newCheckSeuLanCmd())

	return cmd
}

func newHttpConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "http",
		Short:        "HTTP connect the host",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			connectResult, err := network.HttpConnect(args[0])
			if err != nil {
				return err
			}
			logger.Info("HTTP connect result", zap.String("result", connectResult))
			return nil
		},
	}
	return cmd
}

func newCheckLoginServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "login",
		Short:        "Check the connection to login server",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := network.CheckConnectionToLoginServer()
			if err != nil {
				return err
			}
			logger.Info("Connection to login server check success")
			return nil
		},
	}
	return cmd
}

func newCheckSeuLanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "seulan",
		Short:        "Check the connection to SeuLan",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := network.CheckSeuLanConnection()
			if err != nil {
				return err
			}
			logger.Info("Connection to SeuLan check success")
			return nil
		},
	}
	return cmd
}
