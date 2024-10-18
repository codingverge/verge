package logrus

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/ory/x/errorsx"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	gelf "github.com/seatgeek/logrus-gelf-formatter"

	"github.com/ory/x/stringsx"
)

type (
	options struct {
		l             *logrus.Logger
		level         *logrus.Level
		formatter     logrus.Formatter
		format        string
		reportCaller  bool
		exitFunc      func(int)
		leakSensitive bool
		redactionText string
		hooks         []logrus.Hook
		c             configurator
	}
	Option           func(*options)
	nullConfigurator struct{}
	configurator     interface {
		Bool(key string) bool
		String(key string) string
	}
	Logger struct {
		*logrus.Entry
		leakSensitive bool
		redactionText string
		opts          []Option
		name          string
		version       string
	}
)

//go:embed config.schema.json
var ConfigSchema string

const ConfigSchemaID = "verge://logging-config"

// New creates a new logger with all the important fields set.
func New(name string, version string, opts ...Option) *Logger {
	o := newOptions(opts)
	return &Logger{
		opts:          opts,
		name:          name,
		version:       version,
		leakSensitive: o.leakSensitive || o.c.Bool("log.leak_sensitive_values"),
		redactionText: stringsx.Coalesce(o.redactionText, `Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".`),
		Entry: newLogger(o.l, o).WithFields(logrus.Fields{
			"audience": "application", "service_name": name, "service_version": version}),
	}
}

func newOptions(opts []Option) *options {
	o := new(options)
	o.c = new(nullConfigurator)
	for _, f := range opts {
		f(o)
	}
	return o
}

func (c *nullConfigurator) Bool(_ string) bool {
	return false
}

func (c *nullConfigurator) String(_ string) string {
	return ""
}

func NewAudit(name string, version string, opts ...Option) *Logger {
	return New(name, version, opts...).WithField("audience", "audit")
}

func (l *Logger) UseConfig(c configurator) {
	l.leakSensitive = l.leakSensitive || c.Bool("log.leak_sensitive_values")
	l.redactionText = stringsx.Coalesce(c.String("log.redaction_text"), l.redactionText)
	o := newOptions(append(l.opts, WithConfigurator(c)))
	setLevel(l.Entry.Logger, o)
	setFormatter(l.Entry.Logger, o)
}

func (l *Logger) ReportError(r *http.Request, code int, err error, args ...interface{}) {
	logger := l.WithError(err).WithRequest(r).WithField("http_response", map[string]interface{}{
		"status_code": code,
	})
	switch {
	case code < 500:
		logger.Info(args...)
	default:
		logger.Error(args...)
	}
}

func LeakSensitive() Option {
	return func(o *options) {
		o.leakSensitive = true
	}
}

func RedactionText(text string) Option {
	return func(o *options) {
		o.redactionText = text
	}
}

// AddConfigSchema adds the logging schema to the compiler.
// The interface is specified instead of `jsonschema.Compiler` to allow the use of any jsonschema library fork or version.
func AddConfigSchema(c interface {
	AddResource(url string, r io.Reader) error
}) error {
	return c.AddResource(ConfigSchemaID, bytes.NewBufferString(ConfigSchema))
}

func newLogger(parent *logrus.Logger, o *options) *logrus.Logger {
	l := parent
	if l == nil {
		l = logrus.New()
	}

	if o.exitFunc != nil {
		l.ExitFunc = o.exitFunc
	}

	for _, hook := range o.hooks {
		l.AddHook(hook)
	}

	setLevel(l, o)
	setFormatter(l, o)

	l.ReportCaller = o.reportCaller || l.IsLevelEnabled(logrus.TraceLevel)
	return l
}

func setLevel(l *logrus.Logger, o *options) {
	if o.level != nil {
		l.Level = *o.level
	} else {
		var err error
		l.Level, err = logrus.ParseLevel(stringsx.Coalesce(
			o.c.String("log.level"),
			os.Getenv("LOG_LEVEL")))
		if err != nil {
			l.Level = logrus.InfoLevel
		}
	}
}

func setFormatter(l *logrus.Logger, o *options) {
	if o.formatter != nil {
		l.Formatter = o.formatter
	} else {
		var unknownFormat bool // we first have to set the formatter before we can complain about the unknown format

		format := stringsx.SwitchExact(stringsx.Coalesce(o.format, o.c.String("log.format"), os.Getenv("LOG_FORMAT")))
		switch {
		case format.AddCase("json"):
			l.Formatter = &logrus.JSONFormatter{PrettyPrint: false, TimestampFormat: time.RFC3339Nano, DisableHTMLEscape: true}
		case format.AddCase("json_pretty"):
			l.Formatter = &logrus.JSONFormatter{PrettyPrint: true, TimestampFormat: time.RFC3339Nano, DisableHTMLEscape: true}
		case format.AddCase("gelf"):
			l.Formatter = new(gelf.GelfFormatter)
		default:
			unknownFormat = true
			fallthrough
		case format.AddCase("text", ""):
			l.Formatter = &logrus.TextFormatter{
				DisableQuote:     true,
				DisableTimestamp: false,
				FullTimestamp:    true,
			}
		}

		if unknownFormat {
			l.WithError(format.ToUnknownCaseErr()).Warn("got unknown \"log.format\", falling back to \"text\"")
		}
	}
}

func ForceLevel(level logrus.Level) Option {
	return func(o *options) {
		o.level = &level
	}
}

func ForceFormatter(formatter logrus.Formatter) Option {
	return func(o *options) {
		o.formatter = formatter
	}
}

func WithConfigurator(c configurator) Option {
	return func(o *options) {
		o.c = c
	}
}

func ForceFormat(format string) Option {
	return func(o *options) {
		o.format = format
	}
}

func WithHook(hook logrus.Hook) Option {
	return func(o *options) {
		o.hooks = append(o.hooks, hook)
	}
}

func WithExitFunc(exitFunc func(int)) Option {
	return func(o *options) {
		o.exitFunc = exitFunc
	}
}

func ReportCaller(reportCaller bool) Option {
	return func(o *options) {
		o.reportCaller = reportCaller
	}
}

func UseLogger(l *logrus.Logger) Option {
	return func(o *options) {
		o.l = l
	}
}

var opts = otelhttptrace.WithPropagators(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

func (l *Logger) LeakSensitiveData() bool {
	return l.leakSensitive
}

func (l *Logger) Logrus() *logrus.Logger {
	return l.Entry.Logger
}

func (l *Logger) NewEntry() *Logger {
	ll := *l
	ll.Entry = logrus.NewEntry(l.Logger)
	return &ll
}

func (l *Logger) WithContext(ctx context.Context) *Logger {
	ll := *l
	ll.Entry = l.Logger.WithContext(ctx)
	return &ll
}

func (l *Logger) HTTPHeadersRedacted(h http.Header) map[string]interface{} {
	headers := map[string]interface{}{}

	for key, value := range h {
		keyLower := strings.ToLower(key)
		if keyLower == "authorization" || keyLower == "cookie" || keyLower == "set-cookie" || keyLower == "x-session-token" {
			headers[keyLower] = l.maybeRedact(value)
		} else {
			headers[keyLower] = h.Get(key)
		}
	}

	return headers
}

func (l *Logger) WithRequest(r *http.Request) *Logger {
	headers := l.HTTPHeadersRedacted(r.Header)
	if ua := r.UserAgent(); len(ua) > 0 {
		headers["user-agent"] = ua
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	ll := l.WithField("http_request", map[string]interface{}{
		"remote":  r.RemoteAddr,
		"method":  r.Method,
		"path":    r.URL.EscapedPath(),
		"query":   l.maybeRedact(r.URL.RawQuery),
		"scheme":  scheme,
		"host":    r.Host,
		"headers": headers,
	})

	spanCtx := trace.SpanContextFromContext(r.Context())
	if !spanCtx.IsValid() {
		_, _, spanCtx = otelhttptrace.Extract(r.Context(), r, opts)
	}
	if spanCtx.IsValid() {
		traces := make(map[string]string, 2)
		if spanCtx.HasTraceID() {
			traces["trace_id"] = spanCtx.TraceID().String()
		}
		if spanCtx.HasSpanID() {
			traces["span_id"] = spanCtx.SpanID().String()
		}
		ll = ll.WithField("otel", traces)
	}
	return ll
}

func (l *Logger) WithSpanFromContext(ctx context.Context) *Logger {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return l
	}

	traces := make(map[string]string, 2)
	if spanCtx.HasTraceID() {
		traces["trace_id"] = spanCtx.TraceID().String()
	}
	if spanCtx.HasSpanID() {
		traces["span_id"] = spanCtx.SpanID().String()
	}
	return l.WithField("otel", traces)
}

func (l *Logger) Logf(level logrus.Level, format string, args ...interface{}) {
	if !l.leakSensitive {
		for i, arg := range args {
			switch urlArg := arg.(type) {
			case url.URL:
				urlCopy := url.URL{Scheme: urlArg.Scheme, Host: urlArg.Host, Path: urlArg.Path}
				args[i] = urlCopy
			case *url.URL:
				urlCopy := url.URL{Scheme: urlArg.Scheme, Host: urlArg.Host, Path: urlArg.Path}
				args[i] = &urlCopy
			default:
				continue
			}
		}
	}
	l.Entry.Logf(level, format, args...)
}

func (l *Logger) Tracef(format string, args ...interface{}) {
	l.Logf(logrus.TraceLevel, format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logf(logrus.DebugLevel, format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logf(logrus.InfoLevel, format, args...)
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.Infof(format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logf(logrus.WarnLevel, format, args...)
}

func (l *Logger) Warningf(format string, args ...interface{}) {
	l.Warnf(format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logf(logrus.ErrorLevel, format, args...)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logf(logrus.FatalLevel, format, args...)
	l.Entry.Logger.Exit(1)
}

func (l *Logger) Panicf(format string, args ...interface{}) {
	l.Logf(logrus.PanicLevel, format, args...)
}

func (l *Logger) WithFields(f logrus.Fields) *Logger {
	ll := *l
	ll.Entry = l.Entry.WithFields(f)
	return &ll
}

func (l *Logger) WithField(key string, value interface{}) *Logger {
	ll := *l
	ll.Entry = l.Entry.WithField(key, value)
	return &ll
}

func (l *Logger) maybeRedact(value interface{}) interface{} {
	if fmt.Sprintf("%v", value) == "" || value == nil {
		return nil
	}
	if !l.leakSensitive {
		return l.redactionText
	}
	return value
}

func (l *Logger) WithSensitiveField(key string, value interface{}) *Logger {
	return l.WithField(key, l.maybeRedact(value))
}

func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	ctx := map[string]interface{}{"message": err.Error()}
	if l.Entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
		if e, ok := err.(errorsx.StackTracer); ok {
			ctx["stack_trace"] = fmt.Sprintf("%+v", e.StackTrace())
		} else {
			ctx["stack_trace"] = fmt.Sprintf("stack trace could not be recovered from error type %s", reflect.TypeOf(err))
		}
	}
	if c := errorsx.ReasonCarrier(nil); errors.As(err, &c) {
		ctx["reason"] = c.Reason()
	}
	if c := errorsx.RequestIDCarrier(nil); errors.As(err, &c) && c.RequestID() != "" {
		ctx["request_id"] = c.RequestID()
	}
	if c := errorsx.DetailsCarrier(nil); errors.As(err, &c) && c.Details() != nil {
		ctx["details"] = c.Details()
	}
	if c := errorsx.StatusCarrier(nil); errors.As(err, &c) && c.Status() != "" {
		ctx["status"] = c.Status()
	}
	if c := errorsx.StatusCodeCarrier(nil); errors.As(err, &c) && c.StatusCode() != 0 {
		ctx["status_code"] = c.StatusCode()
	}
	if c := errorsx.DebugCarrier(nil); errors.As(err, &c) {
		ctx["debug"] = c.Debug()
	}

	return l.WithField("error", ctx)
}

var popLevelTranslations = map[logging.Level]logrus.Level{
	// logging.SQL:   logrus.TraceLevel, we never want to log SQL statements, see https://github.com/ory/keto/issues/454
	logging.Debug: logrus.DebugLevel,
	logging.Info:  logrus.InfoLevel,
	logging.Warn:  logrus.WarnLevel,
	logging.Error: logrus.ErrorLevel,
}

func (l *Logger) PopLogger(lvl logging.Level, s string, args ...interface{}) {
	level, ok := popLevelTranslations[lvl]
	if ok {
		l.WithField("source", "pop").Logf(level, s, args...)
	}
}
