package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	// Primary colors
	Primary = color.New(color.FgCyan, color.Bold)
	Success = color.New(color.FgGreen, color.Bold)
	Warning = color.New(color.FgYellow, color.Bold)
	Danger  = color.New(color.FgRed, color.Bold)
	Info    = color.New(color.FgBlue, color.Bold)

	// Text styles
	Bold      = color.New(color.Bold)
	Dim       = color.New(color.Faint)
	Underline = color.New(color.Underline)

	// Background colors
	BgRed    = color.New(color.BgRed, color.FgWhite)
	BgGreen  = color.New(color.BgGreen, color.FgBlack)
	BgYellow = color.New(color.BgYellow, color.FgBlack)
	BgBlue   = color.New(color.BgBlue, color.FgWhite)
)

type ColorScheme struct {
	Title     *color.Color
	Header    *color.Color
	Success   *color.Color
	Warning   *color.Color
	Error     *color.Color
	Info      *color.Color
	Highlight *color.Color
	Muted     *color.Color
	Critical  *color.Color
	High      *color.Color
	Medium    *color.Color
	Low       *color.Color
}

var DefaultColorScheme = ColorScheme{
	Title:     color.New(color.FgCyan, color.Bold, color.Underline),
	Header:    color.New(color.FgWhite, color.Bold, color.BgBlue),
	Success:   color.New(color.FgGreen, color.Bold),
	Warning:   color.New(color.FgYellow, color.Bold),
	Error:     color.New(color.FgRed, color.Bold),
	Info:      color.New(color.FgBlue, color.Bold),
	Highlight: color.New(color.FgMagenta, color.Bold),
	Muted:     color.New(color.FgHiBlack),
	Critical:  color.New(color.FgHiRed, color.Bold, color.BlinkSlow),
	High:      color.New(color.FgRed, color.Bold),
	Medium:    color.New(color.FgYellow, color.Bold),
	Low:       color.New(color.FgGreen, color.Bold),
}

var NoColorScheme = ColorScheme{
	Title:     color.New(),
	Header:    color.New(),
	Success:   color.New(),
	Warning:   color.New(),
	Error:     color.New(),
	Info:      color.New(),
	Highlight: color.New(),
	Muted:     color.New(),
	Critical:  color.New(),
	High:      color.New(),
	Medium:    color.New(),
	Low:       color.New(),
}

func GetColorScheme(noColor bool) ColorScheme {
	if noColor {
		return NoColorScheme
	}
	return DefaultColorScheme
}

// Colorize output based on severity
func ColorizeBySeverity(text string, severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return DefaultColorScheme.Critical.Sprint(text)
	case "HIGH":
		return DefaultColorScheme.High.Sprint(text)
	case "MEDIUM":
		return DefaultColorScheme.Medium.Sprint(text)
	case "LOW":
		return DefaultColorScheme.Low.Sprint(text)
	default:
		return DefaultColorScheme.Info.Sprint(text)
	}
}

// Progress bar for terminal
type ProgressBar struct {
	total       int
	current     int
	width       int
	label       string
	showPercent bool
	lastUpdate  string
}

func NewProgressBar(total int, label string) *ProgressBar {
	return &ProgressBar{
		total:       total,
		width:       50,
		label:       label,
		showPercent: true,
	}
}

func (pb *ProgressBar) Increment() {
	pb.current++
	pb.Render()
}

func (pb *ProgressBar) SetCurrent(current int) {
	pb.current = current
	pb.Render()
}

func (pb *ProgressBar) Render() {
	if pb.total == 0 {
		return
	}

	percent := float64(pb.current) / float64(pb.total)
	filledWidth := int(percent * float64(pb.width))

	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", pb.width-filledWidth)

	var output string
	if pb.showPercent {
		output = fmt.Sprintf("\r%s [%s] %3.1f%% (%d/%d)",
			pb.label, bar, percent*100, pb.current, pb.total)
	} else {
		output = fmt.Sprintf("\r%s [%s] (%d/%d)",
			pb.label, bar, pb.current, pb.total)
	}

	// Only update if changed to reduce flicker
	if output != pb.lastUpdate {
		fmt.Print(output)
		pb.lastUpdate = output
	}

	// Add newline when complete
	if pb.current >= pb.total {
		fmt.Println()
	}
}

func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.Render()
}

// Spinner animation for loading states
type Spinner struct {
	frames   []string
	current  int
	active   bool
	label    string
	stopChan chan bool
}

func NewSpinner(label string) *Spinner {
	return &Spinner{
		frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		label:    label,
		active:   false,
		stopChan: make(chan bool, 1),
	}
}

func (s *Spinner) Start() {
	s.active = true
	go func() {
		for {
			select {
			case <-s.stopChan:
				return
			default:
				frame := s.frames[s.current%len(s.frames)]
				fmt.Printf("\r%s %s", frame, s.label)
				s.current++

				// Animation speed
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Stop() {
	if s.active {
		s.stopChan <- true
		s.active = false
		fmt.Println() // Move to next line
	}
}

func (s *Spinner) SetLabel(label string) {
	s.label = label
}

// Box drawing utilities
func DrawBox(title string, content string, boxColor *color.Color) {
	lines := strings.Split(content, "\n")
	maxLength := len(title)
	for _, line := range lines {
		if len(line) > maxLength {
			maxLength = len(line)
		}
	}

	// Add padding
	maxLength += 4

	top := "╔" + strings.Repeat("═", maxLength) + "╗"
	middle := "╠" + strings.Repeat("═", maxLength) + "╣"
	bottom := "╚" + strings.Repeat("═", maxLength) + "╝"

	titleLine := "║ " + title + strings.Repeat(" ", maxLength-len(title)-1) + "║"

	boxColor.Println(top)
	boxColor.Println(titleLine)
	boxColor.Println(middle)

	for _, line := range lines {
		paddedLine := "║ " + line + strings.Repeat(" ", maxLength-len(line)-1) + "║"
		fmt.Println(paddedLine)
	}

	boxColor.Println(bottom)
}

// Table printing utility
func PrintTable(headers []string, rows [][]string) {
	// Calculate column widths
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Add padding
	for i := range colWidths {
		colWidths[i] += 2
	}

	// Print header separator
	printRowSeparator(colWidths, "┬", "┼", "┴")

	// Print headers
	fmt.Print("│")
	for i, header := range headers {
		fmt.Printf(" %-*s │", colWidths[i]-2, header)
	}
	fmt.Println()

	// Print header bottom
	printRowSeparator(colWidths, "├", "┼", "┤")

	// Print rows
	for _, row := range rows {
		fmt.Print("│")
		for i, cell := range row {
			if i < len(colWidths) {
				fmt.Printf(" %-*s │", colWidths[i]-2, cell)
			}
		}
		fmt.Println()
	}

	// Print footer
	printRowSeparator(colWidths, "┴", "┼", "─")
}

func printRowSeparator(widths []int, left, mid, right string) {
	fmt.Print(left)
	for i, w := range widths {
		fmt.Print(strings.Repeat("─", w))
		if i < len(widths)-1 {
			fmt.Print(mid)
		}
	}
	fmt.Println(right)
}

// Check if output supports colors
func SupportsColor() bool {
	// Check for NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check if stdout is a terminal
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Initialize color settings
func InitColors(noColorFlag bool) {
	if noColorFlag || !SupportsColor() {
		color.NoColor = true
	}
}
