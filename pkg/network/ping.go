package network

import (
	"fmt"
	"net"
	"net/http"
	"time"

	loggerPkg "github.com/SmartFPGATutor/seulogin/pkg/logger"
	"go.uber.org/zap"
)

var logger = loggerPkg.GetLogger()

func Ping(host string) (string, error) {
	return ping_impl(host)
}

// ref: https://github.com/nodeseeker/tcping/blob/main/src/main.go
func TCPPing(host string) (string, error) {
	logger.Debug("TCP pinging host", zap.String("host", host))

	stopPing := make(chan bool, 1)

	var sendCount int
	var recvCount int
	var minTime, maxTime, totalTime int64

	go func() {
		for i := 0; i < 10; i++ {
			select {
			case <-stopPing:
				return
			default:
				startTime := time.Now()
				conn, err := net.DialTimeout("tcp", host, time.Second*3)
				elapsedTime := time.Since(startTime).Milliseconds()

				sendCount++
				if err != nil {
					logger.Error("Failed to connect to host", zap.String("host", host), zap.Error(err))
				} else {
					conn.Close()
					recvCount++
					totalTime += elapsedTime
					if elapsedTime < minTime || minTime == 0 {
						minTime = elapsedTime
					}
					if elapsedTime > maxTime {
						maxTime = elapsedTime
					}
					totalTime += elapsedTime
				}
			}
		}
		stopPing <- true
	}()

	<-stopPing

	if sendCount-recvCount > 0 {
		logger.Error("Failed to connect to host", zap.String("host", host), zap.Int("send_count", sendCount), zap.Int("recv_count", recvCount))
		return "", fmt.Errorf("failed to connect to host")
	}

	logger.Debug("TCP ping success", zap.String("host", host), zap.Int("send_count", sendCount), zap.Int("recv_count", recvCount))

	if sendCount == 0 {
		return "", fmt.Errorf("no response from tcp ping")
	}
	avgRtt := fmt.Sprintf("min: %dms, max: %dms, avg: %dms", minTime, maxTime, totalTime/int64(sendCount))
	pingResult := fmt.Sprintf("tcp ping to %s send_count: %d, recv_count: %d, %s", host, sendCount, recvCount, avgRtt)
	return pingResult, nil
}

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
	// tcp ping
	if _, err := TCPPing("www.baidu.com:80"); err != nil {
		return err
	}

	// http connect
	if _, err := HttpConnect("https://www.baidu.com"); err != nil {
		return err
	}

	logger.Debug("Wan connection check success")
	return nil
}

func CheckConnectionToLoginServer() error {
	if _, err := TCPPing("10.80.128.2:802"); err != nil {
		return err
	}

	if _, err := HttpConnect("https://w.seu.edu.cn:802"); err != nil {
		return err
	}

	logger.Debug("Connection to login server check success")
	return nil
}

func CheckSeuLanConnection() error {
	// w.seu.edu.cn
	if _, err := TCPPing("10.80.128.2:802"); err != nil {
		return err
	}

	if _, err := HttpConnect("https://w.seu.edu.cn:802"); err != nil {
		return err
	}

	logger.Debug("SeuLan connection check success")
	return nil
}
