package stackunwind

import (
	"io"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/sirupsen/logrus"
)

var logrusLevelToTraceeLogFunc = map[logrus.Level]func(string, ...interface{}){
	logrus.PanicLevel: logger.Fatalw,
	logrus.FatalLevel: logger.Fatalw,
	logrus.ErrorLevel: logger.Errorw,
	logrus.WarnLevel:  logger.Warnw,
	logrus.InfoLevel:  logger.Infow,
	logrus.DebugLevel: logger.Debugw,
	logrus.TraceLevel: logger.Debugw,
}

type logrusHook struct{}

// Fire is called with every log entry, and here it forwards to Tracee's logger
func (hook *logrusHook) Fire(entry *logrus.Entry) error {
	// Convert logrus entry to our logger's format and log it
	logFunc, exists := logrusLevelToTraceeLogFunc[entry.Level]
	if !exists {
		// Do nothing if the level is unrecognized
		return nil
	}
	logFunc(entry.Message)
	return nil
}

// Levels returns the log levels the hook is activated for
func (hook *logrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func registerLogrusHook() {
	hook := &logrusHook{}
	logrus.AddHook(hook)
	logrus.SetOutput(io.Discard)
}
