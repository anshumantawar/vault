export PATH := $(HOME)/.goenv/shims:$(HOME)/go/bin:$(PATH)

.PHONY: gen build lint test test-short cover demo down bench

gen:
	buf lint && buf generate
	templ generate

build: gen
	go build -o vault ./cmd/vault

lint:
	test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go vet ./...
	staticcheck ./...

test:
	go vet ./...
	go test -race -count=1 ./...

test-short:
	go test -short ./...

cover:
	go test -short -coverprofile=cover.out ./... && go tool cover -func=cover.out | tail -1

demo:
	scripts/demo.sh up

down:
	scripts/demo.sh down

bench:
	go test -run '^$$' -bench . -benchmem ./...
