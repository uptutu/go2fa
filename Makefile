# 2fa Makefile
#
# Common dev targets. CI / release use goreleaser (see .goreleaser.yaml).

BINARY  := 2fa
PKG     := ./cmd/2fa
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w

.PHONY: build test test-race lint fmt vet vendor-jsqr clean cross release

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)
	@echo "built ./$(BINARY)"

test:
	go test ./...

test-race:
	go test -race ./...

lint: vet

vet:
	go vet ./...

fmt:
	gofmt -s -w .

# Download jsQR.js (Apache-2.0) into the embedded static dir.
vendor-jsqr:
	curl -sSL https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js \
	  -o internal/app/web/static/jsqr.min.js
	@echo "vendored jsQR.js"

cross:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64     $(PKG)
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64     $(PKG)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64    $(PKG)
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64    $(PKG)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(PKG)
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-arm64.exe $(PKG)
	@echo "cross-compiled into dist/"

release:
	command -v goreleaser >/dev/null || { echo "goreleaser required: go install github.com/goreleaser/goreleaser@latest"; exit 1; }
	goreleaser release --clean

clean:
	rm -f $(BINARY) dist/$(BINARY)-*