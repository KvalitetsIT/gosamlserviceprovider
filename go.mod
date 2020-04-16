module github.com/KvalitetsIT/gosamlserviceprovider

go 1.14


require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20200416184625-51822bff6698
	github.com/beevik/etree v1.1.0
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.1
	github.com/jonboulle/clockwork v0.1.0
	github.com/pkg/errors v0.8.1
	github.com/russellhaering/gosaml2 v0.3.1
	github.com/russellhaering/goxmldsig v0.0.0-00010101000000-000000000000
	go.uber.org/atomic v1.5.0
	go.uber.org/multierr v1.3.0
	go.uber.org/zap v1.13.0
	gotest.tools v2.2.0+incompatible
)

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace github.com/russellhaering/gosaml2 => github.com/KvalitetsIT/gosaml2 v0.0.0-20200311115749-13fe093be2ad

