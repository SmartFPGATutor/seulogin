package cmd

import (
	"fmt"

	"github.com/SmartFPGATutor/seulogin/internal/configs"
	"github.com/SmartFPGATutor/seulogin/internal/login"
	"github.com/SmartFPGATutor/seulogin/pkg/seulogin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	username   string
	password   string
	ip         string
	rawIP      bool
	configFile string
	useUPnP    bool
	upnpIface  string
)

func newLoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "login",
		Short:        "Use config file to login to seulogin",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configFile != "" {
				err := configs.CheckConfig(configFile)
				if err != nil {
					logger.Error("Failed to check config", zap.Error(err))
					return err
				}
				config, err := configs.LoadConfig(args[0])
				if err != nil {
					logger.Error("Failed to load config", zap.Error(err))
					return err
				}
				return login.LoginWithConfig(config)
			} else {
				if username == "" || password == "" {
					logger.Error("username and password are required")
					return fmt.Errorf("username and password are required")
				}

				useUpnpLogin := useUPnP || upnpIface != ""
				if useUpnpLogin {
					if upnpIface == "" {
						logger.Error("UPnP interface is required")
						return fmt.Errorf("upnp interface is required")
					}
					externalIP, err := seulogin.GetExternalIP(upnpIface)
					if err != nil {
						logger.Error("Failed to get UPnP IP", zap.String("interface", upnpIface), zap.Error(err))
						return fmt.Errorf("get upnp ip failed: %w", err)
					}
					ip = externalIP
				}

				if ip == "" {
					logger.Error("ip is required")
					return fmt.Errorf("ip is required")
				}
				success, msg := seulogin.LoginToSeulogin(username, password, ip, rawIP)
				if !success {
					logger.Error("Login failed", zap.String("message", msg))
					return fmt.Errorf("login failed: %s", msg)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password")
	cmd.Flags().StringVarP(&ip, "ip", "i", "", "ip")
	cmd.Flags().BoolVarP(&rawIP, "raw-ip", "r", false, "use raw ip of login server, not use domain name of login server")
	cmd.Flags().BoolVarP(&useUPnP, "upnp", "U", false, "use UPnP to resolve campus IP (requires interface)")
	cmd.Flags().StringVar(&upnpIface, "upnp-iface", "", "UPnP interface name (e.g. eth0, wlan0)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file")
	return cmd
}
