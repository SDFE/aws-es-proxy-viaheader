FROM golang:1.10-alpine as build

WORKDIR /go/src/github.com/Mendeley/aws-es-proxy
COPY . .

RUN apk add git \
    && go get -v ./...

CMD CGO_ENABLED=0 GOOS=linux go build -o /dist/linux/aws-es-proxy aws-es-proxy.go
