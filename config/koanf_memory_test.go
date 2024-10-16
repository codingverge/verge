package config

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/x/assertx"
)

func TestKoanfMemory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	doc := []byte(`{
  "foo": {
    "bar": "baz"
  }
}`)
	kf := NewKoanfMemory(ctx, doc)

	actual, err := kf.Read()
	require.NoError(t, err)
	assertx.EqualAsJSON(t, json.RawMessage(doc), actual)
}
