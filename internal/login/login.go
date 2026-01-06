package login

import (
	"slices"

	"github.com/SmartFPGATutor/seulogin/internal/configs"
	loggerPkg "github.com/SmartFPGATutor/seulogin/pkg/logger"
	"github.com/SmartFPGATutor/seulogin/pkg/seulogin"
	"go.uber.org/zap"
)

var logger = loggerPkg.GetLogger()

func LoginWithConfig(config *configs.Config) error {
	logger.Info("Login with", zap.Int("Login With IP", len(config.LoginIP)), zap.Int("Login With Interface", len(config.LoginInterface)), zap.Int("Login With UPnP", len(config.LoginUPnP)))

	if len(config.LoginIP) > 0 {
		for _, loginIP := range config.LoginIP {
			logger.Info("Login with", zap.String("Login With IP", *loginIP.IP), zap.Bool("Login With Interface", *loginIP.UseIP))
			success, errMsg := seulogin.LoginToSeulogin(*loginIP.Username, *loginIP.Password, *loginIP.IP, *loginIP.UseIP)
			if !success {
				logger.Error("Failed to login to seulogin", zap.String("username", *loginIP.Username), zap.String("ip", *loginIP.IP), zap.String("errMsg", errMsg))
			}
		}
	}

	if len(config.LoginInterface) > 0 {
		for _, loginInterface := range config.LoginInterface {
			logger.Info("Login with", zap.String("Login With Interface", *loginInterface.Interface), zap.Bool("Login With UseIP", *loginInterface.UseIP))
			ip, err := seulogin.GetInterfaceIP(*loginInterface.Interface)
			if err != nil {
				logger.Error("Failed to get interface IP", zap.String("interfaceName", *loginInterface.Interface), zap.Error(err))
				continue
			}
			success, errMsg := seulogin.LoginToSeulogin(*loginInterface.Username, *loginInterface.Password, ip.String(), *loginInterface.UseIP)
			if !success {
				logger.Error("Failed to login to seulogin", zap.String("username", *loginInterface.Username), zap.String("ip", ip.String()), zap.String("errMsg", errMsg))
			}
		}
	}

	if len(config.LoginUPnP) > 0 {
		for _, loginUPnP := range config.LoginUPnP {
			logger.Info("Login with", zap.String("Login With UPnP", *loginUPnP.Interface), zap.Bool("Login With UseIP", *loginUPnP.UseIP))
			ip, err := seulogin.GetExternalIP(*loginUPnP.Interface)
			if err != nil {
				logger.Error("Failed to get external IP", zap.String("interfaceName", *loginUPnP.Interface), zap.Error(err))
				continue
			}
			if slices.Contains(loginUPnP.Exclude, ip) {
				logger.Warn("current ip is in exclude list", zap.String("ip", ip))
				continue
			}
			success, errMsg := seulogin.LoginToSeulogin(*loginUPnP.Username, *loginUPnP.Password, ip, *loginUPnP.UseIP)
			if !success {
				logger.Error("Failed to login to seulogin", zap.String("username", *loginUPnP.Username), zap.String("ip", ip), zap.String("errMsg", errMsg))
			}
		}
	}

	return nil
}
