module caddy

go 1.13

replace github.com/caddyserver/caddy/v2 => github.com/KvalitetsIT/caddy/v2 v2.0.0-beta9.0.20191202222324-af18d1a7d058

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace gosamlserviceprovider/samlprovider => ../gosamlserviceprovider

require (
  github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20191211203256-073cc6fea877
  github.com/caddyserver/caddy/v2 v2.0.0-00010101000000-000000000000
  go.uber.org/zap v1.13.0
  gosamlserviceprovider/samlprovider v0.0.0-00010101000000-000000000000
)
