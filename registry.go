package verge

import (
	"context"
	_ "embed"
	"github.com/codingverge/verge/logrus"
	"github.com/ory/herodot"
	"github.com/ory/x/contextx"
	"github.com/ory/x/healthx"
	prometheus "github.com/ory/x/prometheusx"
)

type (
	Registry interface {
		Writer() herodot.Writer
		Logger() *logrus.Logger

		Init(ctx context.Context, ctxer contextx.Contextualizer) error

		MetricsHandler() *prometheus.Handler
		HealthHandler(ctx context.Context) *healthx.Handler
	}

	options struct {
	}

	Option           func(*options)
	nullConfigurator struct{}
	configurator     interface {
		Bool(key string) bool
		String(key string) string
	}
)

//go:embed config.schema.json
var ConfigSchema string

const ConfigSchemaID = "verge://registry-config"
