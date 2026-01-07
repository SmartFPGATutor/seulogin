package network

import (
	"net"
	"sort"
	"strings"
)

// InterfaceInfo describes a usable network interface with an IPv4 address.
type InterfaceInfo struct {
	Name string
	IP   string
}

var ignoredPrefixes = []string{
	"lo",
	"docker",
	"br-",
	"veth",
	"vmnet",
	"vboxnet",
	"utun",
	"tun",
	"tap",
	"wg",
	"tailscale",
	"virbr",
	"lxc",
	"podman",
	"nerdctl",
	"zt",
}

// ListUsableInterfaces returns active IPv4 interfaces, excluding loopback and common virtual adapters.
func ListUsableInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var results []InterfaceInfo
	var fallback []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if isIgnoredInterface(name) {
			continue
		}
		ip := firstIPv4(iface)
		if ip == "" {
			continue
		}
		info := InterfaceInfo{Name: iface.Name, IP: ip}
		if iface.Flags&net.FlagBroadcast != 0 {
			results = append(results, info)
		} else {
			fallback = append(fallback, info)
		}
	}

	if len(results) == 0 {
		results = fallback
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results, nil
}

func isIgnoredInterface(name string) bool {
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func firstIPv4(iface net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip[0] == 169 && ip[1] == 254 {
			continue
		}
		return ip.String()
	}
	return ""
}
