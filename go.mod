module github.com/KvalitetsIT/gosamlserviceprovider

go 1.16

require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20200416184625-51822bff6698
	github.com/beevik/etree v1.1.0
	github.com/caddyserver/caddy/v2 v2.4.6
	github.com/google/uuid v1.3.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/russellhaering/gosaml2 v0.3.1
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7
	go.mongodb.org/mongo-driver v1.3.2 // indirect
	go.uber.org/zap v1.19.0
	gotest.tools v2.2.0+incompatible
)

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace github.com/russellhaering/gosaml2 => github.com/KvalitetsIT/gosaml2 v0.0.0-20201030140015-1552cb4e4bec
