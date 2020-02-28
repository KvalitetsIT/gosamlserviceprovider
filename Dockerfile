FROM kit/git as sshsecret

FROM golang:1.13.4 as builder
ENV GO111MODULE=on

# add credentials on build and make sure github.xom is accepted
RUN mkdir /root/.ssh/
COPY --from=sshsecret /id_rsa /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh/id_rsa
RUN touch /root/.ssh/known_hosts
RUN ssh-keyscan github.com >> /root/.ssh/known_hosts
ADD gitconfig /root/.gitconfig

# Prepare for custom caddy build
RUN mkdir /gosamlserviceprovider
WORKDIR /gosamlserviceprovider
ENV GOPRIVATE="github.com/KvalitetsIT/gosecurityprotocol"
ADD go.mod go.mod
RUN go mod download

COPY samlprovider /gosamlserviceprovider/samlprovider
COPY modules /gosamlserviceprovider/modules
COPY caddy /gosamlserviceprovider/caddy
COPY main.go main.go
RUN go test -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/gosamlserviceprovider .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/caddy ./caddy

FROM alpine:3.10.3 as certs
RUN apk --update add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/bin/caddy /usr/bin/caddy
ENTRYPOINT ["/usr/bin/caddy", "run"]

