package network

import (
	"fmt"
	"net/http"
	"time"

	loggerPkg "github.com/SmartFPGATutor/seulogin/pkg/logger"
	"go.uber.org/zap"
)

var logger = loggerPkg.GetLogger()

func HttpConnect(host string) (string, error) {
	logger.Debug("HTTP connecting to host", zap.String("host", host))

	client := http.Client{
		Timeout: time.Second * 3,
	}

	startTime := time.Now()
	_, err := client.Get(host)
	elapsedTime := time.Since(startTime).Milliseconds()
	defer client.CloseIdleConnections()
	if err != nil {
		logger.Error("Failed to connect to host", zap.String("host", host), zap.Error(err))
		return "", err
	}

	logger.Debug("HTTP connect success", zap.String("host", host))

	connectResult := fmt.Sprintf("http connect to %s elapsed_time: %dms", host, elapsedTime)
	return connectResult, nil
}

func CheckWanConnection() error {
	// http connect
	if _, err := HttpConnect("https://www.baidu.com"); err != nil {
		return err
	}

	logger.Debug("Wan connection check success")
	return nil
}

func CheckConnectionToLoginServer() error {
	if _, err := HttpConnect("https://w.seu.edu.cn:802"); err != nil {
		return err
	}

	logger.Debug("Connection to login server check success")
	return nil
}

func CheckSeuLanConnection() error {
	// w.seu.edu.cn
	if _, err := HttpConnect("https://w.seu.edu.cn:802"); err != nil {
		return err
	}

	logger.Debug("SeuLan connection check success")
	return nil
}
