package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/SmartFPGATutor/seulogin/internal/configs"
	"github.com/SmartFPGATutor/seulogin/internal/login"
	"github.com/SmartFPGATutor/seulogin/pkg/network"
	"github.com/SmartFPGATutor/seulogin/pkg/seulogin"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type menuID int

const (
	menuLogin menuID = iota
	menuCron
	menuNetwork
	menuStatus
	menuQuit
)

type menuItem struct {
	id    menuID
	title string
	desc  string
}

func (i menuItem) Title() string       { return i.title }
func (i menuItem) Description() string { return i.desc }
func (i menuItem) FilterValue() string { return i.title }

type netAction int

const (
	netActionWAN netAction = iota
	netActionLoginServer
	netActionSeuLan
	netActionPing
	netActionTCP
	netActionHTTP
)

type loginResultMsg struct {
	success bool
	message string
}

type networkResultMsg struct {
	action string
	err    error
	result string
}

type cronStartMsg struct {
	cron *cron.Cron
	err  error
	expr string
	path string
}

type tuiModel struct {
	menu         list.Model
	active       menuID
	width        int
	height       int
	leftWidth    int
	rightWidth   int
	bodyHeight   int
	status       []string
	lastResult   string
	cron         *cron.Cron
	cronExpr     string
	cronPath     string
	cronRunning  bool
	loginInputs  []textinput.Model
	loginFocus   int
	loginRawIP   bool
	cronInput    textinput.Model
	cronFocus    int
	netAction    netAction
	netInputOn   bool
	netPingInput textinput.Model
	netTCPInput  textinput.Model
	netHTTPInput textinput.Model
}

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(lipgloss.Color("#7DD3FC")).
			Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#334155")).
			Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#38BDF8"))

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F97316"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8"))

	accentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#22D3EE"))

	buttonStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#0EA5E9")).
			Padding(0, 1)

	buttonActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#F97316")).
				Background(lipgloss.Color("#1E293B")).
				Foreground(lipgloss.Color("#FCD34D")).
				Padding(0, 1)
)

func newTuiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "tui",
		Short:        "Interactive TUI for login and network operations",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			items := []list.Item{
				menuItem{id: menuLogin, title: "Login", desc: "账号登录"},
				menuItem{id: menuCron, title: "Cron", desc: "定时任务"},
				menuItem{id: menuNetwork, title: "Network", desc: "网络检测"},
				menuItem{id: menuStatus, title: "Status", desc: "操作记录"},
				menuItem{id: menuQuit, title: "Quit", desc: "退出"},
			}

			menu := list.New(items, list.NewDefaultDelegate(), 0, 0)
			menu.Title = "SEULogin"
			menu.SetFilteringEnabled(false)
			menu.SetShowHelp(false)
			menu.Styles.Title = titleStyle

			model := newTuiModel(menu)
			p := tea.NewProgram(model, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("run tui: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func newTuiModel(menu list.Model) tuiModel {
	loginInputs := make([]textinput.Model, 3)
	loginInputs[0] = textinput.New()
	loginInputs[0].Placeholder = "username"
	loginInputs[0].Prompt = "用户名: "
	loginInputs[0].Focus()

	loginInputs[1] = textinput.New()
	loginInputs[1].Placeholder = "password"
	loginInputs[1].Prompt = "密码: "
	loginInputs[1].EchoMode = textinput.EchoPassword
	loginInputs[1].EchoCharacter = '*'

	loginInputs[2] = textinput.New()
	loginInputs[2].Placeholder = "10.0.0.1"
	loginInputs[2].Prompt = "IP: "

	cronInput := textinput.New()
	cronInput.Prompt = "配置路径: "
	cronInput.SetValue(defaultConfigPath())

	pingInput := textinput.New()
	pingInput.Prompt = "Ping: "
	pingInput.Placeholder = "host"

	tcpInput := textinput.New()
	tcpInput.Prompt = "TCP: "
	tcpInput.Placeholder = "host:port"

	httpInput := textinput.New()
	httpInput.Prompt = "HTTP: "
	httpInput.Placeholder = "https://..."

	return tuiModel{
		menu:         menu,
		active:       menuLogin,
		loginInputs:  loginInputs,
		loginFocus:   0,
		loginRawIP:   false,
		cronInput:    cronInput,
		cronFocus:    0,
		netAction:    netActionWAN,
		netPingInput: pingInput,
		netTCPInput:  tcpInput,
		netHTTPInput: httpInput,
		status:       []string{timestamped("TUI started")},
	}
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (model tea.Model, cmd tea.Cmd) {
	defer func() {
		if r := recover(); r != nil {
			errMsg := fmt.Sprintf("TUI panic: %v", r)
			m.lastResult = errMsg
			m.appendStatus(errMsg)
			logger.Error("TUI panic", zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
			model = m
			cmd = nil
		}
	}()

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.stopCron()
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.reflow()
	}

	switch msg := msg.(type) {
	case loginResultMsg:
		if msg.success {
			m.lastResult = "Login success"
			m.appendStatus("Login success")
		} else {
			m.lastResult = fmt.Sprintf("Login failed: %s", msg.message)
			m.appendStatus(m.lastResult)
		}
		return m, nil
	case networkResultMsg:
		if msg.err != nil {
			m.lastResult = fmt.Sprintf("%s failed: %v", msg.action, msg.err)
		} else {
			m.lastResult = msg.result
		}
		m.appendStatus(m.lastResult)
		return m, nil
	case cronStartMsg:
		if msg.err != nil {
			m.lastResult = fmt.Sprintf("Cron failed: %v", msg.err)
			m.appendStatus(m.lastResult)
			return m, nil
		}
		m.cron = msg.cron
		m.cronExpr = msg.expr
		m.cronPath = msg.path
		m.cronRunning = true
		m.lastResult = fmt.Sprintf("Cron started (%s)", msg.expr)
		m.appendStatus(m.lastResult)
		return m, nil
	}

	m.menu, cmd = m.menu.Update(msg)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if item, ok := m.menu.SelectedItem().(menuItem); ok {
				switch item.id {
				case menuQuit:
					m.stopCron()
					return m, tea.Quit
				default:
					m.active = item.id
				}
			}
		}
	}

	switch m.active {
	case menuLogin:
		return m.updateLogin(msg, cmd)
	case menuCron:
		return m.updateCron(msg, cmd)
	case menuNetwork:
		return m.updateNetwork(msg, cmd)
	default:
		return m, cmd
	}
}

func (m tuiModel) View() (out string) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("TUI view panic", zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
			out = fmt.Sprintf("TUI render error: %v\n\nPress q to quit.", r)
		}
	}()

	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	header := headerStyle.Width(m.width).Render("SEULogin · Control Center")
	body := m.renderBody()
	footer := m.renderFooter()

	return strings.Join([]string{header, body, footer}, "\n")
}

func (m *tuiModel) reflow() {
	if m.width == 0 || m.height == 0 {
		return
	}

	minLeft := 18
	minRight := 24

	left := int(float64(m.width) * 0.3)
	if left < minLeft {
		left = minLeft
	}
	if m.width < minLeft+minRight+1 {
		left = m.width/2 - 1
		if left < 10 {
			left = 10
		}
	}
	if left > m.width-minRight-1 {
		left = m.width - minRight - 1
	}
	if left < 10 {
		left = 10
	}

	right := m.width - left - 1
	if right < minRight {
		right = minRight
	}

	headerHeight := 1
	footerHeight := 1
	bodyHeight := m.height - headerHeight - footerHeight
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	m.leftWidth = left
	m.rightWidth = right
	m.bodyHeight = bodyHeight

	m.menu.SetSize(max(1, left-4), max(1, bodyHeight-4))
}

func (m tuiModel) renderBody() string {
	left := panelStyle.Width(m.leftWidth).Height(m.bodyHeight).Render(m.menu.View())
	right := panelStyle.Width(m.rightWidth).Height(m.bodyHeight).Render(m.renderRight())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m tuiModel) renderFooter() string {
	hint := "Tab: next field · Enter: action · Q: quit"
	if m.active == menuNetwork && m.netInputOn {
		hint = "Tab/Esc: back · Enter: run · Q: quit"
	}
	if m.active == menuLogin {
		hint = "Tab: next field · R: raw-ip · Enter: run · Q: quit"
	}
	return dimStyle.Width(m.width).Render(hint)
}

func (m tuiModel) renderRight() string {
	switch m.active {
	case menuLogin:
		return m.renderLogin()
	case menuCron:
		return m.renderCron()
	case menuNetwork:
		return m.renderNetwork()
	case menuStatus:
		return m.renderStatus()
	default:
		return ""
	}
}

func (m tuiModel) renderLogin() string {
	rows := []string{
		titleStyle.Render("Login"),
		"",
		m.loginInputs[0].View(),
		m.loginInputs[1].View(),
		m.loginInputs[2].View(),
		"",
		m.renderToggle("Raw IP", m.loginRawIP),
		"",
		m.renderButton("Run login", m.loginFocus == 3),
	}

	if m.lastResult != "" {
		rows = append(rows, "", sectionStyle.Render("Last result"), dimStyle.Render(m.lastResult))
	}
	return strings.Join(rows, "\n")
}

func (m tuiModel) renderCron() string {
	status := "Stopped"
	if m.cronRunning {
		status = fmt.Sprintf("Running (%s)", m.cronExpr)
	}

	rows := []string{
		titleStyle.Render("Cron"),
		"",
		m.cronInput.View(),
		"",
		fmt.Sprintf("Status: %s", status),
		"",
		lipgloss.JoinHorizontal(lipgloss.Left,
			m.renderButton("Start", m.cronFocus == 1),
			" ",
			m.renderButton("Stop", m.cronFocus == 2),
		),
	}

	if m.lastResult != "" {
		rows = append(rows, "", sectionStyle.Render("Last result"), dimStyle.Render(m.lastResult))
	}
	return strings.Join(rows, "\n")
}

func (m tuiModel) renderNetwork() string {
	rows := []string{
		titleStyle.Render("Network"),
		"",
		m.renderNetAction(netActionWAN, "Check WAN"),
		m.renderNetAction(netActionLoginServer, "Check Login Server"),
		m.renderNetAction(netActionSeuLan, "Check SEU LAN"),
		"",
		m.renderNetAction(netActionPing, "Ping host"),
		m.netPingInput.View(),
		"",
		m.renderNetAction(netActionTCP, "TCP host:port"),
		m.netTCPInput.View(),
		"",
		m.renderNetAction(netActionHTTP, "HTTP url"),
		m.netHTTPInput.View(),
	}

	if m.lastResult != "" {
		rows = append(rows, "", sectionStyle.Render("Last result"), dimStyle.Render(m.lastResult))
	}
	return strings.Join(rows, "\n")
}

func (m tuiModel) renderStatus() string {
	rows := []string{titleStyle.Render("Status")}
	if len(m.status) == 0 {
		rows = append(rows, dimStyle.Render("No activity yet."))
		return strings.Join(rows, "\n")
	}

	maxLines := m.bodyHeight - 4
	if maxLines < 1 {
		maxLines = 1
	}

	start := 0
	if len(m.status) > maxLines {
		start = len(m.status) - maxLines
	}

	rows = append(rows, m.status[start:]...)
	return strings.Join(rows, "\n")
}

func (m tuiModel) renderToggle(label string, value bool) string {
	state := "off"
	if value {
		state = "on"
	}
	return fmt.Sprintf("%s: %s", label, accentStyle.Render(state))
}

func (m tuiModel) renderButton(label string, active bool) string {
	if active {
		return buttonActiveStyle.Render(label)
	}
	return buttonStyle.Render(label)
}

func (m tuiModel) renderNetAction(action netAction, label string) string {
	prefix := "  "
	if m.netAction == action && !m.netInputOn {
		prefix = "> "
	}
	return fmt.Sprintf("%s%s", prefix, label)
}

func (m tuiModel) updateLogin(msg tea.Msg, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "tab":
			m.loginFocus = (m.loginFocus + 1) % 4
			for i := range m.loginInputs {
				if i == m.loginFocus {
					m.loginInputs[i].Focus()
				} else {
					m.loginInputs[i].Blur()
				}
			}
			return m, cmd
		case "r":
			m.loginRawIP = !m.loginRawIP
			return m, cmd
		case "enter":
			if m.loginFocus == 3 {
				return m, m.runLogin()
			}
		}
	}

	if m.loginFocus < len(m.loginInputs) {
		var inputCmd tea.Cmd
		m.loginInputs[m.loginFocus], inputCmd = m.loginInputs[m.loginFocus].Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	}

	return m, cmd
}

func (m tuiModel) updateCron(msg tea.Msg, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "tab":
			m.cronFocus = (m.cronFocus + 1) % 3
			if m.cronFocus == 0 {
				m.cronInput.Focus()
			} else {
				m.cronInput.Blur()
			}
			return m, cmd
		case "enter":
			switch m.cronFocus {
			case 1:
				return m, m.startCron()
			case 2:
				m.stopCron()
				m.appendStatus("Cron stopped")
				m.lastResult = "Cron stopped"
				return m, cmd
			}
		}
	}

	if m.cronFocus == 0 {
		var inputCmd tea.Cmd
		m.cronInput, inputCmd = m.cronInput.Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	}

	return m, cmd
}

func (m tuiModel) updateNetwork(msg tea.Msg, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		if m.netInputOn {
			switch keyMsg.String() {
			case "tab", "esc":
				m.netInputOn = false
				m.blurNetInputs()
				return m, cmd
			case "enter":
				m.netInputOn = false
				m.blurNetInputs()
				return m, m.runNetworkAction()
			}
		} else {
			switch keyMsg.String() {
			case "up", "k":
				if m.netAction > 0 {
					m.netAction--
				}
				return m, cmd
			case "down", "j":
				if m.netAction < netActionHTTP {
					m.netAction++
				}
				return m, cmd
			case "tab":
				if m.netAction == netActionPing || m.netAction == netActionTCP || m.netAction == netActionHTTP {
					m.netInputOn = true
					m.focusNetInput()
					return m, cmd
				}
			case "enter":
				return m, m.runNetworkAction()
			}
		}
	}

	if m.netInputOn {
		input := m.activeNetInput()
		if input != nil {
			updated, inputCmd := input.Update(msg)
			switch m.netAction {
			case netActionPing:
				m.netPingInput = updated
			case netActionTCP:
				m.netTCPInput = updated
			case netActionHTTP:
				m.netHTTPInput = updated
			}
			return m, tea.Batch(cmd, inputCmd)
		}
	}

	return m, cmd
}

func (m *tuiModel) focusNetInput() {
	m.blurNetInputs()
	if input := m.activeNetInput(); input != nil {
		input.Focus()
	}
}

func (m *tuiModel) blurNetInputs() {
	m.netPingInput.Blur()
	m.netTCPInput.Blur()
	m.netHTTPInput.Blur()
}

func (m *tuiModel) activeNetInput() *textinput.Model {
	switch m.netAction {
	case netActionPing:
		return &m.netPingInput
	case netActionTCP:
		return &m.netTCPInput
	case netActionHTTP:
		return &m.netHTTPInput
	default:
		return nil
	}
}

func (m *tuiModel) runLogin() tea.Cmd {
	username := strings.TrimSpace(m.loginInputs[0].Value())
	password := m.loginInputs[1].Value()
	ip := strings.TrimSpace(m.loginInputs[2].Value())
	if username == "" || password == "" || ip == "" {
		m.lastResult = "Login requires username, password, and IP"
		m.appendStatus(m.lastResult)
		return nil
	}

	m.lastResult = "Logging in..."
	m.appendStatus(m.lastResult)

	return func() tea.Msg {
		success, message := seulogin.LoginToSeulogin(username, password, ip, m.loginRawIP)
		return loginResultMsg{success: success, message: message}
	}
}

func (m *tuiModel) startCron() tea.Cmd {
	path := strings.TrimSpace(m.cronInput.Value())
	if path == "" {
		m.lastResult = "Cron requires config path"
		m.appendStatus(m.lastResult)
		return nil
	}

	resolved := expandPath(path)
	m.lastResult = "Starting cron..."
	m.appendStatus(m.lastResult)

	return func() tea.Msg {
		if err := configs.CheckConfig(resolved); err != nil {
			return cronStartMsg{err: err}
		}
		cfg, err := configs.LoadConfig(resolved)
		if err != nil {
			return cronStartMsg{err: err}
		}
		if cfg.CronExp == nil {
			return cronStartMsg{err: fmt.Errorf("cron_exp is not set")}
		}

		login.CheckConnectionOrLogin(cfg)

		c := cron.New()
		_, err = c.AddFunc(*cfg.CronExp, func() {
			login.CheckConnectionOrLogin(cfg)
		})
		if err != nil {
			return cronStartMsg{err: err}
		}
		c.Start()

		return cronStartMsg{cron: c, expr: *cfg.CronExp, path: resolved}
	}
}

func (m *tuiModel) stopCron() {
	if m.cron != nil {
		m.cron.Stop()
	}
	m.cron = nil
	m.cronRunning = false
	m.cronExpr = ""
}

func (m *tuiModel) runNetworkAction() tea.Cmd {
	switch m.netAction {
	case netActionWAN:
		m.appendStatus("Checking WAN...")
		return func() tea.Msg {
			err := network.CheckWanConnection()
			return networkResultMsg{action: "WAN", err: err, result: "WAN connection ok"}
		}
	case netActionLoginServer:
		m.appendStatus("Checking login server...")
		return func() tea.Msg {
			err := network.CheckConnectionToLoginServer()
			return networkResultMsg{action: "Login server", err: err, result: "Login server reachable"}
		}
	case netActionSeuLan:
		m.appendStatus("Checking SEU LAN...")
		return func() tea.Msg {
			err := network.CheckSeuLanConnection()
			return networkResultMsg{action: "SEU LAN", err: err, result: "SEU LAN reachable"}
		}
	case netActionPing:
		host := strings.TrimSpace(m.netPingInput.Value())
		if host == "" {
			m.lastResult = "Ping requires host"
			m.appendStatus(m.lastResult)
			return nil
		}
		m.appendStatus(fmt.Sprintf("Ping %s", host))
		return func() tea.Msg {
			result, err := network.Ping(host)
			return networkResultMsg{action: "Ping", err: err, result: result}
		}
	case netActionTCP:
		host := strings.TrimSpace(m.netTCPInput.Value())
		if host == "" {
			m.lastResult = "TCP requires host:port"
			m.appendStatus(m.lastResult)
			return nil
		}
		m.appendStatus(fmt.Sprintf("TCP %s", host))
		return func() tea.Msg {
			result, err := network.TCPPing(host)
			return networkResultMsg{action: "TCP", err: err, result: result}
		}
	case netActionHTTP:
		url := strings.TrimSpace(m.netHTTPInput.Value())
		if url == "" {
			m.lastResult = "HTTP requires URL"
			m.appendStatus(m.lastResult)
			return nil
		}
		m.appendStatus(fmt.Sprintf("HTTP %s", url))
		return func() tea.Msg {
			result, err := network.HttpConnect(url)
			return networkResultMsg{action: "HTTP", err: err, result: result}
		}
	default:
		return nil
	}
}

func (m *tuiModel) appendStatus(line string) {
	m.status = append(m.status, timestamped(line))
	if len(m.status) > 200 {
		m.status = m.status[len(m.status)-200:]
	}
}

func timestamped(line string) string {
	return fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
}

func defaultConfigPath() string {
	return "~/.config/seulogin/config.toml"
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
