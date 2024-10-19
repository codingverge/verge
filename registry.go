package verge

import (
	"context"
	"github.com/codingverge/verge/health"
	"github.com/codingverge/verge/logrus"
	"github.com/ory/herodot"
	prometheus "github.com/ory/x/prometheusx"
)

var (
	_ Registry = (*RegistryDefault)(nil)
)

type (
	Registry interface {
		Writer() herodot.Writer
		Logger() *logrus.Logger

		Init(ctx context.Context) error

		Run(ctx context.Context) error

		MetricsHandler() *prometheus.Handler
		HealthHandler(ctx context.Context) *health.Handler
	}
)
