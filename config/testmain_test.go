package config

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreCurrent(),
		// We have the global schema cache that is never closed.
		goleak.IgnoreTopFunction("github.com/dgraph-io/ristretto.(*defaultPolicy).processItems"),
		goleak.IgnoreTopFunction("github.com/dgraph-io/ristretto.(*Cache).processItems"),
	)
}
