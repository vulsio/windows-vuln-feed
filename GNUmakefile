SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
GO := GO111MODULE=on go

.PHONY: all
all: test build

.PHONY: build
build: main.go 
	$(GO) build -o windows-vuln-feed $<

.PHONY: install
install: main.go
	$(GO) install

.PHONY: lint
lint:
	$(GO) install github.com/mgechev/revive@latest
	revive -config ./.revive.toml -formatter plain $(PKGS)

.PHONY: golangci
golangci:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run


.PHONY: vet
vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

.PHONY: fmt
fmt:
	gofmt -w $(SRCS)

.PHONY: fmtcheck
fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

.PHONY: pretest
pretest: lint vet fmtcheck

.PHONY: test
test: pretest
	$(GO) test -cover -v ./... || exit;

.PHONY: clean
clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)