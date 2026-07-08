package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
	SUCCESS_LEVEL
)

type Logger struct {
	level       LogLevel
	output      io.Writer
	errorOutput io.Writer
	file        *os.File
	mutex       sync.RWMutex
	prefix      string
	timestamp   bool
	callerInfo  bool
	colorOutput bool
}

type LogEntry struct {
	Timestamp time.Time
	Level     LogLevel
	Message   string
	Fields    map[string]interface{}
	Caller    string
}

var (
	globalLogger *Logger
	once         sync.Once
)

func init() {
	once.Do(func() {
		globalLogger = NewLogger(INFO, os.Stdout, os.Stderr)
	})
}

func NewLogger(level LogLevel, output, errorOutput io.Writer) *Logger {
	return &Logger{
		level:       level,
		output:      output,
		errorOutput: errorOutput,
		timestamp:   true,
		callerInfo:  false,
		colorOutput: SupportsColor(),
	}
}

func NewFileLogger(level LogLevel, filePath string) (*Logger, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := NewLogger(level, file, file)
	logger.file = file

	return logger, nil
}

func GetGlobalLogger() *Logger {
	return globalLogger
}

func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

func (l *Logger) SetPrefix(prefix string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.prefix = prefix
}

func (l *Logger) EnableTimestamp(enable bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.timestamp = enable
}

func (l *Logger) EnableCallerInfo(enable bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.callerInfo = enable
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

func (l *Logger) Success(format string, args ...interface{}) {
	l.log(SUCCESS_LEVEL, format, args...)
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
	}

	if l.callerInfo {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			// Extract just the filename
			parts := strings.Split(file, "/")
			filename := parts[len(parts)-1]
			entry.Caller = fmt.Sprintf("%s:%d", filename, line)
		}
	}

	formatted := l.formatEntry(entry)

	// Choose appropriate output
	var out io.Writer
	if level >= ERROR {
		out = l.errorOutput
	} else {
		out = l.output
	}

	fmt.Fprintln(out, formatted)
}

func (l *Logger) formatEntry(entry LogEntry) string {
	var builder strings.Builder

	// Timestamp
	if l.timestamp {
		builder.WriteString(entry.Timestamp.Format("2006-01-02 15:04:05"))
		builder.WriteString(" ")
	}

	// Level with color
	levelStr := l.levelToString(entry.Level)
	if l.colorOutput {
		levelStr = l.colorizeLevel(entry.Level, levelStr)
	}
	builder.WriteString(levelStr)
	builder.WriteString(" ")

	// Prefix
	if l.prefix != "" {
		builder.WriteString("[")
		builder.WriteString(l.prefix)
		builder.WriteString("] ")
	}

	// Caller info
	if entry.Caller != "" {
		builder.WriteString("(")
		builder.WriteString(entry.Caller)
		builder.WriteString(") ")
	}

	// Message
	builder.WriteString(entry.Message)

	return builder.String()
}

func (l *Logger) levelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "[DEBUG]"
	case INFO:
		return "[INFO]"
	case WARNING:
		return "[WARN]"
	case ERROR:
		return "[ERROR]"
	case FATAL:
		return "[FATAL]"
	case SUCCESS_LEVEL:
		return "[SUCCESS]"
	default:
		return "[?????]"
	}
}

func (l *Logger) colorizeLevel(level LogLevel, str string) string {
	switch level {
	case DEBUG:
		return color.HiBlackString(str)
	case INFO:
		return color.BlueString(str)
	case WARNING:
		return color.YellowString(str)
	case ERROR:
		return color.RedString(str)
	case FATAL:
		return color.HiRedString(str)
	case SUCCESS_LEVEL:
		return color.GreenString(str)
	default:
		return str
	}
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Global logging convenience functions
func LogDebug(format string, args ...interface{}) {
	globalLogger.Debug(format, args...)
}

func LogInfo(format string, args ...interface{}) {
	globalLogger.Info(format, args...)
}

func LogWarning(format string, args ...interface{}) {
	globalLogger.Warning(format, args...)
}

func LogError(format string, args ...interface{}) {
	globalLogger.Error(format, args...)
}

func LogFatal(format string, args ...interface{}) {
	globalLogger.Fatal(format, args...)
}

func LogSuccess(format string, args ...interface{}) {
	globalLogger.Success(format, args...)
}

// Structured logging with fields
func (l *Logger) WithFields(fields map[string]interface{}) *StructuredLogger {
	return &StructuredLogger{
		logger: l,
		fields: fields,
	}
}

type StructuredLogger struct {
	logger *Logger
	fields map[string]interface{}
}

func (sl *StructuredLogger) Debug(format string, args ...interface{}) {
	sl.log(DEBUG, format, args...)
}

func (sl *StructuredLogger) Info(format string, args ...interface{}) {
	sl.log(INFO, format, args...)
}

func (sl *StructuredLogger) Warning(format string, args ...interface{}) {
	sl.log(WARNING, format, args...)
}

func (sl *StructuredLogger) Error(format string, args ...interface{}) {
	sl.log(ERROR, format, args...)
}

func (sl *StructuredLogger) log(level LogLevel, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	// Append fields to message
	if len(sl.fields) > 0 {
		var fieldStrs []string
		for k, v := range sl.fields {
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}
		msg = msg + " {" + strings.Join(fieldStrs, ", ") + "}"
	}

	sl.logger.log(level, "%s", msg)
}

// Performance timing utility
func (l *Logger) TimeOperation(name string) func() {
	start := time.Now()
	LogInfo("▶ Starting: %s", name)

	return func() {
		duration := time.Since(start)
		LogInfo("◀ Completed: %s in %v", name, duration)
	}
}

// Global timer convenience function
func TimeOperation(name string) func() {
	return globalLogger.TimeOperation(name)
}

// Custom log writer that can filter by level
type FilteredWriter struct {
	writer    io.Writer
	minLevel  LogLevel
	formatter func(LogEntry) string
}

func (fw *FilteredWriter) Write(p []byte) (int, error) {
	return fw.writer.Write(p)
}

// Multi-writer support
type MultiWriter struct {
	writers []io.Writer
}

func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		written, writeErr := w.Write(p)
		if written > n {
			n = written
		}
		if writeErr != nil && err == nil {
			err = writeErr
		}
	}
	return
}

// Rotate log files by size
type RotatingLogger struct {
	*Logger
	filePath    string
	maxSize     int64 // bytes
	currentSize int64
}

func NewRotatingLogger(level LogLevel, filePath string, maxSizeMB int) (*RotatingLogger, error) {
	logger, err := NewFileLogger(level, filePath)
	if err != nil {
		return nil, err
	}

	rl := &RotatingLogger{
		Logger:    logger,
		filePath:  filePath,
		maxSize:   int64(maxSizeMB) * 1024 * 1024,
	}

	// Get current file size
	if stat, err := os.Stat(filePath); err == nil {
		rl.currentSize = stat.Size()
	}

	return rl, nil
}

func (rl *RotatingLogger) Log(level LogLevel, format string, args ...interface{}) {
	msg := rl.formatEntry(LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   fmt.Sprintf(format, args...),
	})

	rl.currentSize += int64(len(msg)) + 1 // +1 for newline

	// Check if rotation needed
	if rl.currentSize >= rl.maxSize {
		rl.rotate()
	}

	rl.Logger.log(level, format, args...)
}

func (rl *RotatingLogger) rotate() {
	if rl.file != nil {
		rl.file.Close()
	}

	// Rename current file
	timestamp := time.Now().Format("20060102_150405")
	oldPath := rl.filePath + "." + timestamp
	os.Rename(rl.filePath, oldPath)

	// Create new file
	file, err := os.OpenFile(rl.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to rotate log file: %v", err)
		return
	}

	rl.file = file
	rl.output = file
	rl.errorOutput = file
	rl.currentSize = 0
}