# Makefile for building and verifying the logstream-exporter on Linux.

APP_NAME := logstream-exporter
VERSION?=1.0.0
COMMIT=$(shell git rev-parse --short HEAD)
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

PKG := ./...
GO ?= go

LDFLAGS=-ldflags "-X 'logstream-exporter/pkg/version.Version=$(VERSION)' \
                  -X 'logstream-exporter/pkg/version.GitCommit=$(COMMIT)' \
                  -X 'logstream-exporter/pkg/version.BuildDate=$(DATE)'"

.PHONY: all deps fmt vet test build build-linux run clean verify

all: build

deps:
	$(GO) mod tidy

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG)

build:
	$(GO) build $(LDFLAGS) -o $(APP_NAME) .

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -trimpath -o $(APP_NAME) .

run:
	$(GO) run $(APP_NAME) -config config.example.yml

verify: fmt vet test build

clean:
	rm -rf $(APP_NAME)
