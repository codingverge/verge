package config

import "context"

type contextKey int

const configContextKey contextKey = iota + 1

func ContextWithConfigOptions(ctx context.Context, opts ...OptionModifier) context.Context {
	return context.WithValue(ctx, configContextKey, opts)
}

func ConfigOptionsFromContext(ctx context.Context) []OptionModifier {
	opts, ok := ctx.Value(configContextKey).([]OptionModifier)
	if !ok {
		return []OptionModifier{}
	}
	return opts
}
