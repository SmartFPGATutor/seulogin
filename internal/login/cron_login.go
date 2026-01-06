package login

import (
	"fmt"
	"time"

	"github.com/nerdneilsfield/seulogin/internal/configs"
	"github.com/nerdneilsfield/seulogin/pkg/network"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

func CheckConnectionOrLogin(config *configs.Config) {
	err := network.CheckWanConnection()
	if err != nil {
		logger.Warn("Failed to check wan connection, try to login", zap.Error(err))
		for i := 0; i < *config.RetryTimes; i++ {
			logger.Info("Try to login", zap.Int("try", i), zap.Int("retry_interval", *config.RetryInterval), zap.Int("retry_times", *config.RetryTimes))
			err := LoginWithConfig(config)
			if err != nil {
				logger.Error("Failed to login", zap.Error(err))
			}

			if err = network.CheckWanConnection(); err == nil {
				logger.Info("Login success")
				break
			} else {
				logger.Warn("Failed to login, try again", zap.Error(err))
			}
			time.Sleep(time.Duration(*config.RetryInterval) * time.Second)
		}
	} else {
		logger.Info("Wan connection is ok, skip login")
	}
}

func CronLogin(config *configs.Config) error {
	if config.CronExp == nil {
		logger.Error("cron_exp is not set")
		return fmt.Errorf("cron_exp is not set")
	}

	CheckConnectionOrLogin(config)

	logger.Info("Cron login started", zap.String("cron_exp", *config.CronExp))

	c := cron.New()
	c.AddFunc(*config.CronExp, func() {
		CheckConnectionOrLogin(config)
	})

	c.Start()

	select {}
}
