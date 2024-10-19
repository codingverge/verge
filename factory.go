package verge

func New(opts ...Option) (RegistryDefault, error) {
	o := newOptions(opts)
	return RegistryDefault{
		l: o.logger,
		w: o.writer,
	}, nil
}
