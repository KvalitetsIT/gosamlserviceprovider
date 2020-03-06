module gosamlserviceprovider

go 1.13.4

require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20200305103405-07b87d8e37d4
	github.com/Masterminds/sprig/v3 v3.0.2 // indirect
	github.com/andybalholm/brotli v1.0.0 // indirect
	github.com/beevik/etree v1.1.0
	github.com/caddyserver/caddy/v2 v2.0.0-beta9
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.3.3 // indirect
	github.com/google/uuid v1.1.1
	github.com/huandu/xstrings v1.3.0 // indirect
	github.com/klauspost/compress v1.10.1 // indirect
	github.com/klauspost/cpuid v1.2.3 // indirect
	github.com/lucas-clemente/quic-go v0.14.4 // indirect
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47 // indirect
	github.com/marten-seemann/qtls v0.7.1 // indirect
	github.com/mholt/certmagic v0.9.3 // indirect
	github.com/miekg/dns v1.1.27 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.4.1
	github.com/prometheus/client_model v0.2.0
	github.com/russellhaering/gosaml2 v0.4.0
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7
	github.com/spf13/cast v1.3.1 // indirect
	go.starlark.net v0.0.0-20200203144150-6677ee5c7211 // indirect
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20200214034016-1d94cc7ab1c6 // indirect
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2 // indirect
	golang.org/x/sys v0.0.0-20200219091948-cb0a6d8edb6c // indirect
	golang.org/x/tools v0.0.0-20200219054238-753a1d49df85 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	gotest.tools v2.2.0+incompatible
)

replace github.com/caddyserver/caddy/v2 => github.com/KvalitetsIT/caddy/v2 v2.0.0-20191207064707-edf22def147c

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace github.com/russellhaering/gosaml2 => github.com/KvalitetsIT/gosaml2 v0.0.0-20200306141034-09d1e546a98a

replace github.com/marten-seemann/qtls => github.com/marten-seemann/qtls v0.4.1

replace github.com/golang/groupcache => github.com/golang/groupcache v0.0.0-20191002201903-404acd9df4cc
