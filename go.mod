module github.com/KvalitetsIT/gosamlserviceprovider

go 1.14

require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20200416184625-51822bff6698
	github.com/beevik/etree v1.1.0 // indirect
	github.com/google/go-cmp v0.4.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/client_model v0.2.0
	github.com/russellhaering/gosaml2 v0.3.1 // indirect
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7 // indirect
	go.uber.org/zap v1.15.0
	gotest.tools v2.2.0+incompatible
)

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace github.com/russellhaering/gosaml2 => github.com/KvalitetsIT/gosaml2 v0.0.0-20201030140015-1552cb4e4bec
