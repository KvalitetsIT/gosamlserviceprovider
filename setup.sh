#!/bin/bash

go mod init gosamlserviceprovider
echo "replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig latest" >> go.mod
GOPRIVATE="github.com/KvalitetsIT/gosecurityprotocol"
go get github.com/KvalitetsIT/gosecurityprotocol
go get github.com/russellhaering/gosaml2
go get gotest.tools/assert