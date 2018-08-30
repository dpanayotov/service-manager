/*
 * Copyright 2018 The Service Manager Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package log

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

type logKey struct{}

// LevelKey is the context key for the log level
type LevelKey struct{}

var (
	supportedFormatters = map[string]logrus.Formatter{
		"json": &logrus.JSONFormatter{},
		"text": &logrus.TextFormatter{},
	}
	mux          = sync.Mutex{}
	once         = sync.Once{}
	defaultEntry = logrus.NewEntry(logrus.StandardLogger())
	// C is an alias for ForContext
	C = ForContext
	// R is an alias for ForContextProvider
	R = ForContextProvider
	// D is an alias for Default
	D = Default
)

const (
	// FieldComponentName is the key of the component field in the log message.
	FieldComponentName = "component"
	// FieldCorrelationID is the key of the correlation id field in the log message.
	FieldCorrelationID = "correlation_id"
)

// Contexter interface
type Contexter interface {
	Context() context.Context
}

// Settings type to be loaded from the environment
type Settings struct {
	Level  string
	Format string
}

// DefaultSettings returns default values for Log settings
func DefaultSettings() *Settings {
	return &Settings{
		Level:  "debug",
		Format: "text",
	}
}

// Validate validates the logging settings
func (s *Settings) Validate() error {
	if len(s.Level) == 0 {
		return fmt.Errorf("validate Settings: LogLevel missing")
	}
	if len(s.Format) == 0 {
		return fmt.Errorf("validate Settings: LogFormat missing")
	}
	return nil
}

// Configure creates a new context with a logger using the provided settings.
func Configure(ctx context.Context, settings *Settings) context.Context {
	once.Do(func() {
		level, err := logrus.ParseLevel(settings.Level)
		if err != nil {
			panic(fmt.Sprintf("Could not parse log level configuration: %s", err))
		}
		formatter, ok := supportedFormatters[settings.Format]
		if !ok {
			panic(fmt.Sprintf("Invalid log format: %s", settings.Format))
		}
		logrus.SetLevel(level)
		logrus.SetFormatter(formatter)
		logger := &logrus.Logger{
			Formatter: formatter,
			Level:     level,
			Out:       os.Stdout,
			Hooks:     make(logrus.LevelHooks),
		}
		defaultEntry = logrus.NewEntry(logger)
		defaultEntry.Level = level
	})
	return ContextWithLogger(ctx, defaultEntry)
}

// ForContext retrieves the current logger from the context, configured for the provided component.
// Optionally keys mapped to values from the context can be provided.
// If no logger is present in the context, the default logger is returned
func ForContext(ctx context.Context, component string, keys ...interface{}) *logrus.Entry {
	entry := ctx.Value(logKey{})
	if entry == nil {
		// copy so that changes to the new entry do not reflect the default entry
		entry = copyEntry(defaultEntry)
	}
	fields := make(logrus.Fields, len(keys)+1)
	fields[FieldComponentName] = component
	for _, key := range keys {
		value := ctx.Value(key)
		if value != nil {
			fields[fmt.Sprint(key)] = value
		}
	}
	logEntry := entry.(*logrus.Entry).WithFields(fields)
	contextLogLevel, exists := ctx.Value(LevelKey{}).(string)
	if exists {
		level, err := logrus.ParseLevel(contextLogLevel)
		if err != nil {
			logEntry.Warnf("Dynamic log level change not supported for log level %s", contextLogLevel)
		} else {
			logEntry.Logger.Level = level
			logEntry.Level = level
		}
	}
	return logEntry
}

// ForContextProvider retrieves the current logger from the context provided.
func ForContextProvider(contexter Contexter, component string, keys ...interface{}) *logrus.Entry {
	return ForContext(contexter.Context(), component, keys)
}

// Default returns the default logger configured for the provided component.
func Default(component string, keys ...interface{}) *logrus.Entry {
	return ForContext(context.Background(), component, keys)
}

// ContextWithLogger returns a new context with the provided logger.
func ContextWithLogger(ctx context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(ctx, logKey{}, entry)
}

// RegisterFormatter registers a new logrus Formatter with the given name.
// Returns an error if there is a formatter with the same name.
func RegisterFormatter(name string, formatter logrus.Formatter) error {
	mux.Lock()
	defer mux.Unlock()
	if _, exists := supportedFormatters[name]; exists {
		return fmt.Errorf("Formatter with name %s is already registered", name)
	}
	supportedFormatters[name] = formatter
	return nil
}

func copyEntry(entry *logrus.Entry) *logrus.Entry {
	return &logrus.Entry{
		Logger: &logrus.Logger{
			Level:     entry.Logger.Level,
			Formatter: entry.Logger.Formatter,
			Hooks:     entry.Logger.Hooks,
			Out:       entry.Logger.Out,
		},
		Level:   entry.Level,
		Data:    entry.Data,
		Time:    entry.Time,
		Message: entry.Message,
		Buffer:  entry.Buffer,
	}
}