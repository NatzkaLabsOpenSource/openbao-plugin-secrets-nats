GO_ARCH ?= $(shell go env GOARCH)

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

DOCKER_REGISTRY ?= siredmar
VERSION ?= $(shell git describe --tags --always --dirty)

generate:
	go generate ./...

all: fmt build start

build: generate
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(GO_ARCH) go build -o build/openbao/plugins/openbao-plugin-secrets-nats-$(OS)-$(GO_ARCH) -gcflags "all=-N -l" -ldflags '-extldflags "-static"' cmd/openbao-plugin-secrets-nats/main.go

docker: build
	docker build -t $(DOCKER_REGISTRY)/openbao-with-nats-secrets:$(VERSION) -f build/openbao/Dockerfile .

push: docker
	docker push $(DOCKER_REGISTRY)/openbao-with-nats-secrets:$(VERSION)

start:
	bao server -dev -dev-root-token-id=root -dev-plugin-dir=./build/openbao/plugins -log-level=trace -dev-listen-address=127.0.0.1:8200

enable:
	VAULT_ADDR='http://127.0.0.1:8200' bao secrets enable -path=nats-secrets openbao-plugin-secrets-nats-$(OS)-$(GO_ARCH)

clean:
	rm -f ./build/openbao/plugins/openbao-plugin-secrets-nats-*

fmt:
	go fmt $$(go list ./...)

test:
	go clean -testcache
	go test ./...
	go vet ./...

example:
	VAULT_ADDR='http://127.0.0.1:8200' example/config.sh
	docker kill nats
	docker network rm nats

example-start:
	VAULT_ADDR='http://127.0.0.1:8200' example/config.sh

example-stop:
	docker kill nats
	docker network rm nats

.PHONY: build clean fmt start enable test generate example example-start example-stop
