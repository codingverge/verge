package verge

import (
	"context"
	"github.com/codingverge/verge/logrus"
	"github.com/ory/herodot"
	"github.com/ory/x/contextx"
	"github.com/ory/x/healthx"
	prometheus "github.com/ory/x/prometheusx"
)

func New() (RegistryDefault, error) {
	return RegistryDefault{}, nil
}

type RegistryDefault struct {
	l *logrus.Logger
	w herodot.Writer

	Name    string
	Version string
}

func (r *RegistryDefault) Init(ctx context.Context, ctxer contextx.Contextualizer) error {
	//TODO implement me
	panic("implement me")
}

func (r *RegistryDefault) MetricsHandler() *prometheus.Handler {
	//TODO implement me
	panic("implement me")
}

func (r *RegistryDefault) HealthHandler(ctx context.Context) *healthx.Handler {
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
		r.l = logrus.New(r.Name, r.Version)
	}
	return r.l
}
