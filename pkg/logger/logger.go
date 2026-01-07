package logger

import (
	"os"

	"go.uber.org/zap"
	_ "go.uber.org/zap" // 防止被 go mod tidy 移除
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	structLogger *zap.Logger
	verbose      bool
	saveToFile   bool
	logFilePath  string
	consoleOut   bool
}

var (
	logger = NewLogger(false, false, "", true)
)

func GetLogger() *Logger {
	if logger == nil {
		logger = NewLogger(false, false, "", true)
	}
	return logger
}

func NewLogger(verbose bool, saveToFile bool, logFilePath string, consoleOut bool) *Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	var structLogger *zap.Logger
	var cores []zapcore.Core

	if saveToFile {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			panic(err)
		}
		level := zapcore.InfoLevel
		if verbose {
			level = zapcore.DebugLevel
		}
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.NewMultiWriteSyncer(zapcore.AddSync(file)),
			zap.LevelEnablerFunc(func(l zapcore.Level) bool {
				return l >= level
			}),
		)
		cores = append(cores, fileCore)
	}

	if consoleOut {
		level := zapcore.InfoLevel
		if verbose {
			level = zapcore.DebugLevel
		}
		stdoutCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zap.LevelEnablerFunc(func(l zapcore.Level) bool {
				return l >= level
			}),
		)
		cores = append(cores, stdoutCore)
	}

	if len(cores) == 0 {
		structLogger = zap.NewNop()
	} else {
		structLogger = zap.New(zapcore.NewTee(cores...))
	}

	return &Logger{
		structLogger: structLogger,
		verbose:      verbose,
		saveToFile:   saveToFile,
		logFilePath:  logFilePath,
		consoleOut:   consoleOut,
	}
}

func (l *Logger) SetVerbose(verbose_ bool) {
	l.verbose = verbose_
}

func (l *Logger) SetSaveToFile(saveToFile_ bool) {
	l.saveToFile = saveToFile_
}

func (l *Logger) SetLogFilePath(logFilePath_ string) {
	l.logFilePath = logFilePath_
}

func (l *Logger) SetConsoleOutput(consoleOut bool) {
	l.consoleOut = consoleOut
}

func (l *Logger) Reset() {
	l.Close()
	newLogger := NewLogger(l.verbose, l.saveToFile, l.logFilePath, l.consoleOut)
	*l = *newLogger // 使用解引用来更新整个 Logger 结构
	l.Debug("Reset logger", zap.String("logFilePath", l.logFilePath), zap.Bool("verbose", l.verbose), zap.Bool("saveToFile", l.saveToFile))
}

func (l *Logger) Info(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Info(msg, args...)
	}
}

func (l *Logger) Error(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Error(msg, args...)
	}
}

func (l *Logger) Fatal(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Fatal(msg, args...)
	}
}

func (l *Logger) Debug(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Debug(msg, args...)
	}
}

func (l *Logger) Panic(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Panic(msg, args...)
	}
}

func (l *Logger) Warn(msg string, args ...zapcore.Field) {
	if l.structLogger != nil {
		l.structLogger.Warn(msg, args...)
	}
}

func (l *Logger) Sync() {
	if l.structLogger != nil {
		l.structLogger.Sync()
	}
}

func (l *Logger) SyncLogs() {
	if l.structLogger != nil {
		l.structLogger.Sync()
	}
}

func (l *Logger) GetVerbose() bool {
	return l.verbose
}

func (l *Logger) Close() {
	if l.structLogger != nil {
		l.structLogger.Sync()
	}
}
