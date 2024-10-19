package verge

import (
	"bytes"
	"context"
	_ "embed"
	"github.com/codingverge/verge/health"
	"github.com/codingverge/verge/logrus"
	"github.com/ory/herodot"
	prometheus "github.com/ory/x/prometheusx"
	"google.golang.org/grpc"
	"io"
	"net/http"
)

type (
	RegistryDefault struct {
		l  *logrus.Logger
		w  herodot.Writer
		hh health.Handler

		name    string
		version string
	}

	options struct {
		logger *logrus.Logger
		writer herodot.Writer
		config configurator

		httpMiddlewares        []func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc)
		grpcUnaryInterceptors  []grpc.UnaryServerInterceptor
		grpcStreamInterceptors []grpc.StreamServerInterceptor
	}

	Option           func(*options)
	nullConfigurator struct{}
	configurator     interface {
		Bool(key string) bool
		String(key string) string
	}
)

func (r *RegistryDefault) Run(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (n nullConfigurator) Bool(key string) bool {
	return false
}

func (n nullConfigurator) String(key string) string {
	return ""
}

func (r *RegistryDefault) Init(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (r *RegistryDefault) MetricsHandler() *prometheus.Handler {
	//TODO implement me
	panic("implement me")
}

func (r *RegistryDefault) HealthHandler(ctx context.Context) *health.Handler {
	//TODO implement me
	panic("implement me")
}

func (r *RegistryDefault) Writer() herodot.Writer {
	if r.w == nil {
		h := herodot.NewJSONWriter(r.Logger())
		r.w = h
	}
	return r.w
}

func (r *RegistryDefault) Logger() *logrus.Logger {
	if r.l == nil {
		r.l = logrus.New(r.name, r.version)
	}
	return r.l
}

//go:embed config.schema.json
var ConfigSchema string

const ConfigSchemaID = "verge://registry-config"

// AddConfigSchema adds the logging schema to the compiler.
// The interface is specified instead of `jsonschema.Compiler` to allow the use of any jsonschema library fork or version.
func AddConfigSchema(c interface {
	AddResource(url string, r io.Reader) error
}) error {
	return c.AddResource(ConfigSchemaID, bytes.NewBufferString(ConfigSchema))
}

func WithLogger(l *logrus.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

func WithConfigurator(c configurator) Option {
	return func(o *options) {
		o.config = c
	}
}

func newOptions(opts []Option) *options {
	o := new(options)
	o.config = new(nullConfigurator)
	for _, f := range opts {
		f(o)
	}
	return o
}
