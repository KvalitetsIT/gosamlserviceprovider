module github.com/KvalitetsIT/gosamlserviceprovider

go 1.13.4

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20191211203256-073cc6fea877
	github.com/caddyserver/caddy/v2 v2.0.0-beta9
	github.com/google/go-cmp v0.4.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/gosaml2 v0.4.0
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/tools v0.0.0-20200216192241-b320d3a0f5a2 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	gotest.tools v2.2.0+incompatible
)
