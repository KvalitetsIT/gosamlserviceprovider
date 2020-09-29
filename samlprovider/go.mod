module github.com/KvalitetsIT/gosamlserviceprovider

go 1.14

require (
	github.com/KvalitetsIT/gosecurityprotocol v0.0.0-20200506140209-281b8e0d6539
	github.com/beevik/etree v1.1.0
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/google/uuid v1.1.2
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/gosaml2 v0.3.1
	github.com/russellhaering/goxmldsig v0.0.0-20180430223755-7acd5e4a6ef7
	go.uber.org/zap v1.16.0
	gotest.tools v2.2.0+incompatible
)

replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig v0.0.0-20190907195011-53d9398322c5

replace github.com/russellhaering/gosaml2 => github.com/KvalitetsIT/gosaml2 v0.0.0-20200311115749-13fe093be2ad
