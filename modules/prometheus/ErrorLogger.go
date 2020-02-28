package prometheus

import "go.uber.org/zap"

type ErrorLogger struct {
	logger *zap.SugaredLogger
}

func NewErrorLogger(logger *zap.SugaredLogger) *ErrorLogger {
	return &ErrorLogger{logger}
}

func (l *ErrorLogger) Println(args ...interface{}) {
	l.logger.Error(args)

}
