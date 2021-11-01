#FROM golang:1.16.9 as builder
FROM golang:1.16.9 as builder
ENV GO111MODULE=on

# Prepare for custom caddy build
RUN mkdir /gosamlserviceprovider
WORKDIR /gosamlserviceprovider
ADD go.mod go.mod
ADD go.sum go.sum
RUN go mod download

COPY samlprovider /gosamlserviceprovider/samlprovider

WORKDIR /gosamlserviceprovider/samlprovider

RUN go test -coverprofile=coverage.out -v ./...
RUN go tool cover -func=coverage.out
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/gosamlserviceprovider .