package verge

import (
	"context"
	"github.com/ory/x/contextx"
	"github.com/ory/x/dbal"
	"github.com/ory/x/healthx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	prometheus "github.com/ory/x/prometheusx"
)

type (
	Registry interface {
		dbal.Driver

		Init(ctx context.Context, ctxer contextx.Contextualizer, opts ...RegistryOption) error

		WithLogger(l *logrusx.Logger) Registry

		MetricsHandler() *prometheus.Handler
		HealthHandler(ctx context.Context) *healthx.Handler
	}

	RegistryOption func(*options)

	options struct {
		replaceTracer func(*otelx.Tracer) *otelx.Tracer
		inspect       func(Registry) error
	}
)

func newOptions(os []RegistryOption) *options {
	o := new(options)
	for _, f := range os {
		f(o)
	}
	return o
}
