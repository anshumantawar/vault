export PATH := $(HOME)/.goenv/shims:$(HOME)/go/bin:$(PATH)

.PHONY: gen build test test-short demo down bench

gen:
	buf lint && buf generate
	templ generate

build: gen
	go build -o vault ./cmd/vault

test:
	go vet ./...
	go test -race -count=1 ./...

test-short:
	go test -short ./...

demo:
	scripts/demo.sh up

down:
	scripts/demo.sh down

bench:
	go test -run '^$$' -bench . -benchmem ./...
