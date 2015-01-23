GOPATH := $(shell pwd)

lint:
	@go get github.com/golang/lint/golint
	@$(GOPATH)/bin/golint java/*.go

test:
	@cd java; go test; cd - 1>/dev/null

.PHONY: lint test
