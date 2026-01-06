package seulogin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"go.uber.org/zap"
)

// GetExternalIP 获取指定接口的路由器Wan口IP
func GetExternalIP(interfaceName string) (string, error) {
	ip, err := GetInterfaceIP(interfaceName)
	if err != nil {
		logger.Error("Failed to get interface %s IP", zap.String("interfaceName", interfaceName), zap.Error(err))
		return "", err
	}

	httpClient, err := createHttpClient(ip)
	if err != nil {
		logger.Error("Failed to create HTTP client", zap.String("interfaceName", interfaceName), zap.Error(err))
		return "", err
	}

	externalIP, err := getExternalIPv1(httpClient)
	if err != nil || externalIP == "" {
		logger.Error("Failed to get external IP using IGD v1", zap.String("interfaceName", interfaceName), zap.Error(err))
		externalIP, err = getExternalIPv2(httpClient)
		if err != nil || externalIP == "" {
			logger.Error("Failed to get external IP using IGD v2", zap.String("interfaceName", interfaceName), zap.Error(err))
			return "", err
		}
	}

	return externalIP, nil
}

// GetInterfaceIP 获取指定接口的 IP 地址, 如果接口不存在, 则返回错误
func GetInterfaceIP(interfaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		logger.Error("Failed to get interface", zap.String("interfaceName", interfaceName), zap.Error(err))
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		logger.Error("Failed to get addresses for interface", zap.String("interfaceName", interfaceName), zap.Error(err))
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}

	logger.Error("No IP address found for interface", zap.String("interfaceName", interfaceName))
	return nil, fmt.Errorf("no IP address found for interface %s", interfaceName)
}

func createHttpClient(localIP net.IP) (*http.Client, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: localIP},
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	return &http.Client{Transport: transport}, nil
}

func getExternalIPs(getIPsFunc func() ([]string, error)) ([]string, error) {
	ips, err := getIPsFunc()
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// getExternalIPv1 使用IGDv1获取外网IP
func getExternalIPv1(httpClient *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		logger.Error("Failed to get IGD v1 clients", zap.Error(err))
		return "", err
	}
	if len(clients) == 0 {
		logger.Error("No UPnP clients found")
		return "", fmt.Errorf("no UPnP clients found")
	}

	for _, client := range clients {
		client.SOAPClient.HTTPClient = *httpClient
		ip, err := client.GetExternalIPAddress()
		if err == nil && ip != "" {
			logger.Debug("External IP using IGD v1", zap.String("ip", ip))
			return ip, nil
		}
	}
	logger.Error("Could not get external IP using IGD v1")
	return "", fmt.Errorf("could not get external IP using IGD v1")
}

// getExternalIPv2 使用IGDv2获取外网IP
func getExternalIPv2(httpClient *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err != nil {
		logger.Error("Failed to get IGD v2 clients", zap.Error(err))
		return "", err
	}
	if len(clients) == 0 {
		logger.Error("No UPnP clients found")
		return "", fmt.Errorf("no UPnP clients found")
	}

	for _, client := range clients {
		client.SOAPClient.HTTPClient = *httpClient
		ip, err := client.GetExternalIPAddress()
		if err == nil && ip != "" {
			logger.Debug("External IP using IGD v2", zap.String("ip", ip))
			return ip, nil
		}
	}

	logger.Error("Could not get external IP using IGD v2")
	return "", fmt.Errorf("could not get external IP using IGD v2")
}
