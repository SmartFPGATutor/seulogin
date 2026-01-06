package main

import (
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/SmartFPGATutor/seulogin/internal/configs"
	"github.com/SmartFPGATutor/seulogin/internal/login"
	"github.com/SmartFPGATutor/seulogin/pkg/network"
	"github.com/SmartFPGATutor/seulogin/pkg/seulogin"
	"github.com/robfig/cron/v3"
)

type guiState struct {
	app           fyne.App
	statusLabel   *widget.Label
	statusScroll  *container.Scroll
	statusLines   []string
	loginStatus   *widget.Label
	cronStatus    *widget.Label
	networkStatus *widget.Label
	cron          *cron.Cron
}

func main() {
	app := app.New()
	w := app.NewWindow("SEULogin GUI")
	w.Resize(fyne.NewSize(900, 640))

	state := newGUIState(app)
	header := buildHeader()
	content := widget.NewAppTabs(
		widget.NewTabItem("Login", buildLoginTab(state)),
		widget.NewTabItem("Network", buildNetworkTab(state)),
		widget.NewTabItem("Cron", buildCronTab(state)),
		widget.NewTabItem("Status", buildStatusTab(state)),
	)

	w.SetContent(container.NewBorder(header, nil, nil, nil, content))
	w.SetCloseIntercept(func() {
		state.stopCron()
		w.Close()
	})

	w.ShowAndRun()
}

func newGUIState(app fyne.App) *guiState {
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord
	statusScroll := container.NewVScroll(statusLabel)
	statusScroll.SetMinSize(fyne.NewSize(300, 200))

	return &guiState{
		app:           app,
		statusLabel:   statusLabel,
		statusScroll:  statusScroll,
		statusLines:   []string{},
		loginStatus:   widget.NewLabel(""),
		cronStatus:    widget.NewLabel(""),
		networkStatus: widget.NewLabel(""),
	}
}

func buildHeader() fyne.CanvasObject {
	bg := canvas.NewRectangle(color.NRGBA{R: 46, G: 125, B: 50, A: 255})
	title := canvas.NewText("SEU · 东南大学校园网", color.NRGBA{R: 241, G: 248, B: 233, A: 255})
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.TextSize = 22
	subtitle := canvas.NewText("SEULogin GUI", color.NRGBA{R: 220, G: 231, B: 117, A: 255})
	subtitle.TextSize = 14

	text := container.NewVBox(title, subtitle)
	textPad := container.NewPadded(text)
	return container.NewMax(bg, textPad)
}

func buildLoginTab(state *guiState) fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("username")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("password")

	ip := widget.NewEntry()
	ip.SetPlaceHolder("10.0.0.1")

	rawIP := widget.NewCheck("使用登录节点 IP (raw-ip)", nil)

	form := widget.NewForm(
		widget.NewFormItem("用户名", username),
		widget.NewFormItem("密码", password),
		widget.NewFormItem("IP", ip),
	)
	form.SubmitText = "登录"
	form.CancelText = "清空"
	form.OnSubmit = func() {
		user := strings.TrimSpace(username.Text)
		pass := password.Text
		addr := strings.TrimSpace(ip.Text)
		if user == "" || pass == "" || addr == "" {
			state.setLoginStatus("请输入用户名、密码与 IP")
			state.appendStatus("Login: missing username/password/IP")
			return
		}

		state.setLoginStatus("正在登录...")
		state.appendStatus("Login started")

		go func() {
			if _, err := network.HttpConnect("https://w.seu.edu.cn:802"); err != nil {
				state.setLoginStatus("无法连接登录服务器，可能不在东南大学校园网。")
				state.appendStatus("Login blocked: not reachable")
				return
			}
			success, msg := seulogin.LoginToSeulogin(user, pass, addr, rawIP.Checked)
			if success {
				state.setLoginStatus("登录成功")
				state.appendStatus("Login success")
				return
			}
			state.setLoginStatus(friendlyLoginError(msg))
			state.appendStatus("Login failed")
		}()
	}
	form.OnCancel = func() {
		username.SetText("")
		password.SetText("")
		ip.SetText("")
		rawIP.SetChecked(false)
		state.setLoginStatus("")
	}

	statusCard := widget.NewCard("状态", "", state.loginStatus)
	return container.NewVBox(form, rawIP, statusCard, layout.NewSpacer())
}

func buildNetworkTab(state *guiState) fyne.CanvasObject {
	pingEntry := widget.NewEntry()
	pingEntry.SetPlaceHolder("host")
	tcpEntry := widget.NewEntry()
	tcpEntry.SetPlaceHolder("host:port")
	httpEntry := widget.NewEntry()
	httpEntry.SetPlaceHolder("https://...")

	wanBtn := widget.NewButton("检查外网", func() {
		state.runNetworkAction("WAN", func() error {
			return network.CheckWanConnection()
		})
	})
	loginBtn := widget.NewButton("检查登录服务器", func() {
		state.runNetworkAction("Login server", func() error {
			return network.CheckConnectionToLoginServer()
		})
	})
	seuBtn := widget.NewButton("检查 SEU LAN", func() {
		state.runNetworkAction("SEU LAN", func() error {
			return network.CheckSeuLanConnection()
		})
	})

	pingBtn := widget.NewButton("Ping", func() {
		host := strings.TrimSpace(pingEntry.Text)
		if host == "" {
			state.setNetworkStatus("请输入 Ping 目标")
			state.appendStatus("Ping: missing host")
			return
		}
		state.runNetworkAction("Ping", func() error {
			_, err := network.Ping(host)
			return err
		})
	})

	tcpBtn := widget.NewButton("TCP", func() {
		host := strings.TrimSpace(tcpEntry.Text)
		if host == "" {
			state.setNetworkStatus("请输入 host:port")
			state.appendStatus("TCP: missing host")
			return
		}
		state.runNetworkAction("TCP", func() error {
			_, err := network.TCPPing(host)
			return err
		})
	})

	httpBtn := widget.NewButton("HTTP", func() {
		url := strings.TrimSpace(httpEntry.Text)
		if url == "" {
			state.setNetworkStatus("请输入 URL")
			state.appendStatus("HTTP: missing url")
			return
		}
		state.runNetworkAction("HTTP", func() error {
			_, err := network.HttpConnect(url)
			return err
		})
	})

	checkCard := widget.NewCard("基础检测", "", container.NewVBox(wanBtn, loginBtn, seuBtn))
	customCard := widget.NewCard("自定义", "", container.NewVBox(
		container.NewBorder(nil, nil, nil, pingBtn, pingEntry),
		container.NewBorder(nil, nil, nil, tcpBtn, tcpEntry),
		container.NewBorder(nil, nil, nil, httpBtn, httpEntry),
	))
	statusCard := widget.NewCard("状态", "", state.networkStatus)

	return container.NewVBox(checkCard, customCard, statusCard, layout.NewSpacer())
}

func buildCronTab(state *guiState) fyne.CanvasObject {
	configPath := widget.NewEntry()
	configPath.SetText(defaultConfigPath())

	startBtn := widget.NewButton("启动", func() {
		path := strings.TrimSpace(configPath.Text)
		if path == "" {
			state.setCronStatus("请输入配置文件路径")
			state.appendStatus("Cron: missing config path")
			return
		}

		state.setCronStatus("正在启动...")
		state.appendStatus("Cron start requested")

		go func() {
			resolved := expandPath(path)
			if err := configs.CheckConfig(resolved); err != nil {
				state.setCronStatus(fmt.Sprintf("配置错误: %v", err))
				state.appendStatus("Cron config invalid")
				return
			}
			cfg, err := configs.LoadConfig(resolved)
			if err != nil {
				state.setCronStatus(fmt.Sprintf("读取失败: %v", err))
				state.appendStatus("Cron config load failed")
				return
			}
			if cfg.CronExp == nil {
				state.setCronStatus("配置缺少 cron_exp")
				state.appendStatus("Cron config missing cron_exp")
				return
			}

			login.CheckConnectionOrLogin(cfg)

			c := cron.New()
			_, err = c.AddFunc(*cfg.CronExp, func() {
				login.CheckConnectionOrLogin(cfg)
			})
			if err != nil {
				state.setCronStatus(fmt.Sprintf("启动失败: %v", err))
				state.appendStatus("Cron start failed")
				return
			}
			c.Start()
			state.setCron(c)
			state.setCronStatus(fmt.Sprintf("运行中 (%s)", *cfg.CronExp))
			state.appendStatus("Cron started")
		}()
	})

	stopBtn := widget.NewButton("停止", func() {
		state.stopCron()
		state.setCronStatus("已停止")
		state.appendStatus("Cron stopped")
	})

	buttons := container.NewHBox(startBtn, stopBtn)
	statusCard := widget.NewCard("状态", "", state.cronStatus)

	return container.NewVBox(
		widget.NewCard("配置", "", container.NewBorder(nil, nil, nil, nil, configPath)),
		buttons,
		statusCard,
		layout.NewSpacer(),
	)
}

func buildStatusTab(state *guiState) fyne.CanvasObject {
	return container.NewBorder(nil, nil, nil, nil, state.statusScroll)
}

func (s *guiState) appendStatus(line string) {
	s.app.Driver().RunOnMain(func() {
		stamp := time.Now().Format("15:04:05")
		entry := fmt.Sprintf("[%s] %s", stamp, line)
		s.statusLines = append(s.statusLines, entry)
		if len(s.statusLines) > 200 {
			s.statusLines = s.statusLines[len(s.statusLines)-200:]
		}
		s.statusLabel.SetText(strings.Join(s.statusLines, "\n"))
		if s.statusScroll != nil {
			s.statusScroll.ScrollToBottom()
		}
	})
}

func (s *guiState) setLoginStatus(text string) {
	s.setLabel(s.loginStatus, text)
}

func (s *guiState) setCronStatus(text string) {
	s.setLabel(s.cronStatus, text)
}

func (s *guiState) setNetworkStatus(text string) {
	s.setLabel(s.networkStatus, text)
}

func (s *guiState) setLabel(label *widget.Label, text string) {
	s.app.Driver().RunOnMain(func() {
		label.SetText(text)
	})
}

func (s *guiState) runNetworkAction(name string, action func() error) {
	state := s
	state.setNetworkStatus("正在检查...")
	state.appendStatus(fmt.Sprintf("Network: %s", name))

	go func() {
		err := action()
		if err != nil {
			state.setNetworkStatus(fmt.Sprintf("%s 失败: %v", name, err))
			state.appendStatus(fmt.Sprintf("%s failed", name))
			return
		}
		state.setNetworkStatus(fmt.Sprintf("%s 正常", name))
		state.appendStatus(fmt.Sprintf("%s ok", name))
	}()
}

func (s *guiState) setCron(c *cron.Cron) {
	s.app.Driver().RunOnMain(func() {
		s.cron = c
	})
}

func (s *guiState) stopCron() {
	s.app.Driver().RunOnMain(func() {
		if s.cron != nil {
			s.cron.Stop()
		}
		s.cron = nil
	})
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.config/seulogin/config.toml"
	}
	return filepath.Join(home, ".config", "seulogin", "config.toml")
}

func expandPath(path string) string {
	if path == "" {
		return path
	}
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}

func friendlyLoginError(message string) string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "eof") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "context deadline exceeded") ||
		strings.Contains(lower, "tls") {
		return "无法连接登录服务器，可能不在东南大学校园网。"
	}
	return message
}
