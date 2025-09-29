#!/bin/make

GOROOT:=/pkg/main/sys-devel.edgelessrt-bin.dev/go
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

TARGET=vpnetd-sgx

all: $(TARGET)-bundle

clean:
	$(RM) $(TARGET) $(TARGET)-bundle

$(TARGET)-bundle: $(TARGET) docker
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego bundle $<

$(TARGET): *.go go.mod docker
	GOROOT="$(GOROOT)" $(GOPATH)/bin/goimports -w -l .
	docker run --rm -v $(CURDIR):/src -v $(HOME)/go:/go -w /src --user $(shell id -u):$(shell id -g) --env GOCACHE=/go/.cache ubuntu-ego ego-go build -o $@ .
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego sign $@
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego uniqueid $@

.PHONY: docker stdgo

docker:
ifeq ($(shell docker images -q ubuntu-ego),)
	docker build -t ubuntu-ego .
endif

stdgo:
	make clean
	@echo " *** WARNING: Building a non-enclave version of vpnetd-sgx for debugging!!!!!"
	GOROOT="$(GOROOT)" $(GOPATH)/bin/goimports -w -l .
	CGO_ENABLED=1 /pkg/main/dev-lang.go.dev/bin/go build -o $(TARGET) .
	cp $(TARGET) $(TARGET)-bundle

