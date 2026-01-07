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
	netActionHTTP
)

type loginField int

const (
	loginFieldUser loginField = iota
	loginFieldPass
	loginFieldIP
	loginFieldUPnP
	loginFieldUPnPFetch
	loginFieldRun
)

type ifaceOption struct {
	name string
	ip   string
}

type loginResultMsg struct {
	success bool
	message string
}

type upnpResultMsg struct {
	ip  string
	err error
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

type panicMsg struct {
	where string
	value any
}

type tuiModel struct {
	menu           list.Model
	active         menuID
	width          int
	height         int
	leftWidth      int
	rightWidth     int
	bodyHeight     int
	status         []string
	lastResult     string
	cron           *cron.Cron
	cronExpr       string
	cronPath       string
	cronRunning    bool
	loginInputs    []textinput.Model
	loginFocus     int
	loginRawIP     bool
	loginUseUPnP   bool
	loginUpnpInput textinput.Model
	upnpOptions    []ifaceOption
	upnpIndex      int
	upnpLoadErr    string
	cronInput      textinput.Model
	cronFocus      int
	netAction      netAction
	netInputOn     bool
	netHTTPInput   textinput.Model
}

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F1F8E9")).
			Background(lipgloss.Color("#2E7D32")).
			Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7CB342")).
			Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#DCE775"))

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#AED581"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#B0BEC5"))

	accentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F0F4C3"))

	buttonStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7CB342")).
			Padding(0, 1)

	buttonActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#DCE775")).
				Background(lipgloss.Color("#558B2F")).
				Foreground(lipgloss.Color("#F1F8E9")).
				Padding(0, 1)
)

const asciiSEU = `  ____  _____ _   _
 / ___|| ____| | | |
 \___ \|  _| | | | |
  ___) | |___| |_| |
 |____/|_____|\___/`

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

			delegate := list.NewDefaultDelegate()
			delegate.Styles.NormalTitle = dimStyle
			delegate.Styles.NormalDesc = dimStyle
			delegate.Styles.SelectedTitle = accentStyle
			delegate.Styles.SelectedDesc = accentStyle
			delegate.Styles.DimmedTitle = dimStyle
			delegate.Styles.DimmedDesc = dimStyle

			menu := list.New(items, delegate, 0, 0)
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

	upnpInput := textinput.New()
	upnpInput.Placeholder = "eth0 / wlan0"
	upnpInput.Prompt = "UPnP 接口: "

	cronInput := textinput.New()
	cronInput.Prompt = "配置路径: "
	cronInput.SetValue(defaultConfigPath())

	httpInput := textinput.New()
	httpInput.Prompt = "HTTP: "
	httpInput.Placeholder = "https://..."

	upnpOptions, upnpErr := loadUpnpOptions()

	return tuiModel{
		menu:           menu,
		active:         menuLogin,
		loginInputs:    loginInputs,
		loginFocus:     0,
		loginRawIP:     false,
		loginUseUPnP:   false,
		loginUpnpInput: upnpInput,
		upnpOptions:    upnpOptions,
		upnpLoadErr:    upnpErr,
		cronInput:      cronInput,
		cronFocus:      0,
		netAction:      netActionWAN,
		netHTTPInput:   httpInput,
		status:         []string{timestamped("TUI started")},
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
	case upnpResultMsg:
		if msg.err != nil {
			m.lastResult = fmt.Sprintf("UPnP IP failed: %v", msg.err)
			m.appendStatus(m.lastResult)
			return m, nil
		}
		m.loginInputs[2].SetValue(msg.ip)
		m.lastResult = fmt.Sprintf("UPnP IP: %s", msg.ip)
		m.appendStatus(m.lastResult)
		return m, nil
	case panicMsg:
		m.lastResult = fmt.Sprintf("TUI panic (%s): %v", msg.where, msg.value)
		m.appendStatus(m.lastResult)
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

	header := headerStyle.Width(m.width).Render("SEU · 东南大学校园网 · Control Center")
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
	left := panelStyle.Width(m.leftWidth).Height(m.bodyHeight).Render(m.renderMenuPanel())
	right := panelStyle.Width(m.rightWidth).Height(m.bodyHeight).Render(m.renderRight())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m tuiModel) renderMenuPanel() string {
	menuTitle := titleStyle.Render("Menu")
	art := m.menuArt()
	artHeight := lipgloss.Height(art)
	menuHeight := max(1, m.bodyHeight-4-artHeight-2)
	m.menu.SetSize(max(1, m.leftWidth-4), menuHeight)

	if art == "" {
		return lipgloss.JoinVertical(lipgloss.Left, menuTitle, "", m.menu.View())
	}
	return lipgloss.JoinVertical(lipgloss.Left, menuTitle, art, "", m.menu.View())
}

func (m tuiModel) menuArt() string {
	if m.bodyHeight < 12 {
		return accentStyle.Render("SEU")
	}
	name := dimStyle.Render("东南大学 · SOUTHEAST UNIVERSITY")
	return lipgloss.JoinVertical(lipgloss.Left, accentStyle.Render(asciiSEU), name)
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
		titleStyle.Render("Login · 东南大学校园网"),
		"",
		m.loginInputs[0].View(),
		m.loginInputs[1].View(),
		m.loginInputs[2].View(),
		"",
		m.renderToggle("UPnP IP", m.loginUseUPnP),
	}
	if m.loginUseUPnP {
		rows = append(rows, m.loginUpnpInput.View(), dimStyle.Render("UPnP 开启时忽略 IP 输入"))
		if m.upnpLoadErr != "" {
			rows = append(rows, dimStyle.Render("UPnP 接口获取失败: "+m.upnpLoadErr))
		} else if len(m.upnpOptions) == 0 {
			rows = append(rows, dimStyle.Render("未找到可用网卡"))
		} else {
			rows = append(rows, sectionStyle.Render("Interfaces (↑/↓ 选择)"))
			for i, opt := range m.upnpOptions {
				prefix := "  "
				if i == m.upnpIndex {
					prefix = "> "
				}
				rows = append(rows, fmt.Sprintf("%s%s (%s)", prefix, opt.name, opt.ip))
			}
		}
		rows = append(rows, "", m.renderButton("Fetch UPnP IP", m.currentLoginField() == loginFieldUPnPFetch))
		if resolved := strings.TrimSpace(m.loginInputs[2].Value()); resolved != "" {
			rows = append(rows, dimStyle.Render("Resolved IP: "+resolved))
		}
	}
	rows = append(rows,
		"",
		m.renderToggle("Raw IP", m.loginRawIP),
		"",
		m.renderButton("Run login", m.currentLoginField() == loginFieldRun),
	)

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
		m.renderNetAction(netActionHTTP, "HTTP url (curl)"),
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

func loadUpnpOptions() ([]ifaceOption, string) {
	infos, err := network.ListUsableInterfaces()
	if err != nil {
		return nil, err.Error()
	}
	options := make([]ifaceOption, 0, len(infos))
	for _, info := range infos {
		options = append(options, ifaceOption{name: info.Name, ip: info.IP})
	}
	return options, ""
}

func (m *tuiModel) setUpnpFromIndex() {
	if len(m.upnpOptions) == 0 {
		return
	}
	if m.upnpIndex < 0 {
		m.upnpIndex = 0
	}
	if m.upnpIndex >= len(m.upnpOptions) {
		m.upnpIndex = len(m.upnpOptions) - 1
	}
	m.loginUpnpInput.SetValue(m.upnpOptions[m.upnpIndex].name)
}

func (m tuiModel) loginFocusOrder() []loginField {
	fields := []loginField{loginFieldUser, loginFieldPass}
	if !m.loginUseUPnP {
		fields = append(fields, loginFieldIP)
	} else {
		fields = append(fields, loginFieldUPnP, loginFieldUPnPFetch)
	}
	fields = append(fields, loginFieldRun)
	return fields
}

func (m *tuiModel) syncLoginFocus() {
	for i := range m.loginInputs {
		m.loginInputs[i].Blur()
	}
	m.loginUpnpInput.Blur()

	order := m.loginFocusOrder()
	if len(order) == 0 {
		return
	}
	if m.loginFocus < 0 {
		m.loginFocus = 0
	}
	if m.loginFocus >= len(order) {
		m.loginFocus = len(order) - 1
	}

	switch order[m.loginFocus] {
	case loginFieldUser:
		m.loginInputs[0].Focus()
	case loginFieldPass:
		m.loginInputs[1].Focus()
	case loginFieldIP:
		m.loginInputs[2].Focus()
	case loginFieldUPnP:
		m.loginUpnpInput.Focus()
	case loginFieldUPnPFetch:
	case loginFieldRun:
	default:
	}
}

func (m tuiModel) currentLoginField() loginField {
	order := m.loginFocusOrder()
	if len(order) == 0 {
		return loginFieldRun
	}
	if m.loginFocus < 0 {
		return order[0]
	}
	if m.loginFocus >= len(order) {
		return order[len(order)-1]
	}
	return order[m.loginFocus]
}

func (m tuiModel) updateLogin(msg tea.Msg, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		if m.loginUseUPnP && (m.currentLoginField() == loginFieldUPnP || m.currentLoginField() == loginFieldUPnPFetch) {
			switch keyMsg.String() {
			case "up", "k":
				if len(m.upnpOptions) > 0 {
					if m.upnpIndex > 0 {
						m.upnpIndex--
					}
					m.setUpnpFromIndex()
					return m, cmd
				}
			case "down", "j":
				if len(m.upnpOptions) > 0 {
					if m.upnpIndex < len(m.upnpOptions)-1 {
						m.upnpIndex++
					}
					m.setUpnpFromIndex()
					return m, cmd
				}
			}
		}
		switch keyMsg.String() {
		case "tab":
			order := m.loginFocusOrder()
			if len(order) == 0 {
				return m, cmd
			}
			m.loginFocus = (m.loginFocus + 1) % len(order)
			m.syncLoginFocus()
			return m, cmd
		case "r":
			m.loginRawIP = !m.loginRawIP
			return m, cmd
		case "u":
			m.loginUseUPnP = !m.loginUseUPnP
			if m.loginUseUPnP {
				m.upnpOptions, m.upnpLoadErr = loadUpnpOptions()
				current := strings.TrimSpace(m.loginUpnpInput.Value())
				if current == "" {
					m.setUpnpFromIndex()
				} else {
					for i, opt := range m.upnpOptions {
						if opt.name == current {
							m.upnpIndex = i
							break
						}
					}
				}
			}
			m.syncLoginFocus()
			return m, cmd
		case "enter":
			switch m.currentLoginField() {
			case loginFieldUPnPFetch:
				return m, m.fetchUpnpIP()
			case loginFieldRun:
				return m, m.runLogin()
			}
		}
	}

	switch m.currentLoginField() {
	case loginFieldUser:
		var inputCmd tea.Cmd
		m.loginInputs[0], inputCmd = m.loginInputs[0].Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	case loginFieldPass:
		var inputCmd tea.Cmd
		m.loginInputs[1], inputCmd = m.loginInputs[1].Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	case loginFieldIP:
		var inputCmd tea.Cmd
		m.loginInputs[2], inputCmd = m.loginInputs[2].Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	case loginFieldUPnP:
		var inputCmd tea.Cmd
		m.loginUpnpInput, inputCmd = m.loginUpnpInput.Update(msg)
		return m, tea.Batch(cmd, inputCmd)
	case loginFieldUPnPFetch:
		return m, cmd
	default:
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
				if m.netAction == netActionHTTP {
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
	m.netHTTPInput.Blur()
}

func (m *tuiModel) activeNetInput() *textinput.Model {
	switch m.netAction {
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
	if username == "" || password == "" {
		m.lastResult = "Login requires username and password"
		m.appendStatus(m.lastResult)
		return nil
	}
	if !m.loginUseUPnP && ip == "" {
		m.lastResult = "Login requires IP"
		m.appendStatus(m.lastResult)
		return nil
	}

	m.lastResult = "Logging in..."
	m.appendStatus(m.lastResult)

	return safeCmd("login", func() tea.Msg {
		if _, err := network.HttpConnect("https://w.seu.edu.cn:802"); err != nil {
			return loginResultMsg{success: false, message: "无法连接登录服务器，可能不在东南大学校园网。"}
		}
		if m.loginUseUPnP {
			iface := strings.TrimSpace(m.loginUpnpInput.Value())
			if iface == "" {
				return loginResultMsg{success: false, message: "UPnP 接口不能为空"}
			}
			externalIP, err := seulogin.GetExternalIP(iface)
			if err != nil {
				return loginResultMsg{success: false, message: fmt.Sprintf("UPnP 获取 IP 失败: %v", err)}
			}
			ip = externalIP
		}
		success, message := seulogin.LoginToSeulogin(username, password, ip, m.loginRawIP)
		if !success {
			message = friendlyLoginError(message)
		}
		return loginResultMsg{success: success, message: message}
	})
}

func (m *tuiModel) fetchUpnpIP() tea.Cmd {
	if !m.loginUseUPnP {
		m.lastResult = "UPnP is disabled"
		m.appendStatus(m.lastResult)
		return nil
	}
	iface := strings.TrimSpace(m.loginUpnpInput.Value())
	if iface == "" {
		m.lastResult = "UPnP interface is empty"
		m.appendStatus(m.lastResult)
		return nil
	}
	m.lastResult = "Fetching UPnP IP..."
	m.appendStatus(m.lastResult)
	return safeCmd("upnp-fetch", func() tea.Msg {
		ip, err := seulogin.GetExternalIP(iface)
		return upnpResultMsg{ip: ip, err: err}
	})
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

	return safeCmd("cron", func() tea.Msg {
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
	})
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
		return safeCmd("network-wan", func() tea.Msg {
			err := network.CheckWanConnection()
			return networkResultMsg{action: "WAN", err: err, result: "WAN connection ok"}
		})
	case netActionLoginServer:
		m.appendStatus("Checking login server...")
		return safeCmd("network-login", func() tea.Msg {
			err := network.CheckConnectionToLoginServer()
			return networkResultMsg{action: "Login server", err: err, result: "Login server reachable"}
		})
	case netActionSeuLan:
		m.appendStatus("Checking SEU LAN...")
		return safeCmd("network-seulan", func() tea.Msg {
			err := network.CheckSeuLanConnection()
			return networkResultMsg{action: "SEU LAN", err: err, result: "SEU LAN reachable"}
		})
	case netActionHTTP:
		url := strings.TrimSpace(m.netHTTPInput.Value())
		if url == "" {
			m.lastResult = "HTTP requires URL"
			m.appendStatus(m.lastResult)
			return nil
		}
		m.appendStatus(fmt.Sprintf("HTTP %s", url))
		return safeCmd("network-http", func() tea.Msg {
			result, err := network.HttpConnect(url)
			return networkResultMsg{action: "HTTP", err: err, result: result}
		})
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

func safeCmd(where string, fn func() tea.Msg) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("TUI command panic", zap.Any("panic", r), zap.ByteString("stack", debug.Stack()), zap.String("where", where))
				msg = panicMsg{where: where, value: r}
			}
		}()
		return fn()
	}
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
