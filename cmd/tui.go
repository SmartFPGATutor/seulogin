package cmd

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type commandItem struct {
	path string
	cmd  *cobra.Command
}

func (i commandItem) Title() string {
	return i.path
}

func (i commandItem) Description() string {
	if i.cmd.Short == "" {
		return "No description"
	}
	return i.cmd.Short
}

func (i commandItem) FilterValue() string {
	return i.path + " " + i.cmd.Short
}

type keyMap struct {
	Up          key.Binding
	Down        key.Binding
	Filter      key.Binding
	ClearFilter key.Binding
	Help        key.Binding
	Quit        key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Filter, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Filter},
		{k.ClearFilter, k.Help, k.Quit},
	}
}

type tuiModel struct {
	list       list.Model
	help       help.Model
	keys       keyMap
	root       *cobra.Command
	width      int
	height     int
	showHelp   bool
	leftWidth  int
	rightWidth int
	bodyHeight int
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
)

func newTuiCmd(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "tui",
		Short:        "Interactive TUI for commands and options",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			items := collectCommandItems(root)
			l := list.New(items, list.NewDefaultDelegate(), 0, 0)
			l.Title = "SEULogin Commands"
			l.SetFilteringEnabled(true)
			l.SetShowHelp(false)
			l.Styles.Title = titleStyle
			l.Styles.FilterPrompt = dimStyle
			l.Styles.FilterCursor = dimStyle

			keys := keyMap{
				Up:          key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
				Down:        key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
				Filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
				ClearFilter: key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "clear")),
				Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
				Quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
			}

			m := tuiModel{
				list:     l,
				help:     help.New(),
				keys:     keys,
				root:     root,
				showHelp: true,
			}

			p := tea.NewProgram(m, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("run tui: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.showHelp = !m.showHelp
		case key.Matches(msg, m.keys.ClearFilter):
			if m.list.FilterState() != list.Filtering && m.list.FilterState() != list.FilterApplied {
				break
			}
			m.list.ResetFilter()
			return m, nil
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.reflow()
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m tuiModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	header := headerStyle.Width(m.width).Render("SEULogin · Command Explorer")
	body := m.renderBody()
	footer := m.renderFooter()

	return strings.Join([]string{header, body, footer}, "\n")
}

func (m *tuiModel) reflow() {
	if m.width == 0 || m.height == 0 {
		return
	}

	left := int(float64(m.width) * 0.38)
	if left < 30 {
		left = 30
	}
	if left > m.width-24 {
		left = m.width - 24
	}
	if left < 20 {
		left = 20
	}

	right := m.width - left - 1
	if right < 20 {
		right = 20
	}

	headerHeight := 1
	footerHeight := 1
	bodyHeight := m.height - headerHeight - footerHeight
	if bodyHeight < 6 {
		bodyHeight = 6
	}

	m.leftWidth = left
	m.rightWidth = right
	m.bodyHeight = bodyHeight

	m.list.SetSize(left-6, bodyHeight-4)
}

func (m tuiModel) renderBody() string {
	left := panelStyle.Width(m.leftWidth).Height(m.bodyHeight).Render(m.list.View())
	right := panelStyle.Width(m.rightWidth).Height(m.bodyHeight).Render(m.renderDetails())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m tuiModel) renderFooter() string {
	if !m.showHelp {
		return dimStyle.Width(m.width).Render("Press ? to show help")
	}
	return dimStyle.Width(m.width).Render(m.help.View(m.keys))
}

func (m tuiModel) renderDetails() string {
	item, ok := m.list.SelectedItem().(commandItem)
	if !ok || item.cmd == nil {
		return "Select a command to see its options."
	}

	cmd := item.cmd
	sections := []string{
		titleStyle.Render(cmd.CommandPath()),
	}
	if cmd.Short != "" {
		sections = append(sections, dimStyle.Render(cmd.Short))
	}

	sections = append(sections,
		sectionStyle.Render("Usage"),
		cmd.UseLine(),
	)

	localFlags := collectFlags(cmd.NonInheritedFlags())
	if len(localFlags) > 0 {
		sections = append(sections, sectionStyle.Render("Flags"))
		sections = append(sections, formatFlags(localFlags))
	}

	inheritedFlags := collectFlags(cmd.InheritedFlags())
	if len(inheritedFlags) > 0 {
		sections = append(sections, sectionStyle.Render("Inherited Flags"))
		sections = append(sections, formatFlags(inheritedFlags))
	}

	return strings.Join(sections, "\n\n")
}

func collectCommandItems(root *cobra.Command) []list.Item {
	items := []list.Item{}
	if root != nil {
		items = append(items, commandItem{path: root.CommandPath(), cmd: root})
	}

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		for _, sub := range cmd.Commands() {
			if sub.Hidden || sub.Deprecated != "" {
				continue
			}
			if sub.Name() == "help" || sub.Name() == "tui" {
				continue
			}
			items = append(items, commandItem{path: sub.CommandPath(), cmd: sub})
			walk(sub)
		}
	}

	if root != nil {
		walk(root)
	}

	sort.Slice(items, func(i, j int) bool {
		left, okLeft := items[i].(commandItem)
		right, okRight := items[j].(commandItem)
		if !okLeft || !okRight {
			return false
		}
		return left.path < right.path
	})

	return items
}

type flagInfo struct {
	name      string
	shorthand string
	usage     string
	defValue  string
}

func collectFlags(flags *pflag.FlagSet) []flagInfo {
	if flags == nil {
		return nil
	}

	var out []flagInfo
	flags.VisitAll(func(flag *pflag.Flag) {
		out = append(out, flagInfo{
			name:      flag.Name,
			shorthand: flag.Shorthand,
			usage:     flag.Usage,
			defValue:  flag.DefValue,
		})
	})

	sort.Slice(out, func(i, j int) bool {
		return out[i].name < out[j].name
	})
	return out
}

func formatFlags(flags []flagInfo) string {
	if len(flags) == 0 {
		return ""
	}

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 2, 2, ' ', 0)
	for _, flag := range flags {
		label := "--" + flag.name
		if flag.shorthand != "" {
			label = "-" + flag.shorthand + ", " + label
		}
		desc := flag.usage
		if flag.defValue != "" {
			desc = fmt.Sprintf("%s (default: %s)", desc, flag.defValue)
		}
		fmt.Fprintf(writer, "%s\t%s\n", label, desc)
	}
	writer.Flush()
	return builder.String()
}
