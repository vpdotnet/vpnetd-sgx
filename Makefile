#!/bin/make

TARGET=vpnetd-sgx

all: $(TARGET)-bundle

clean:
	$(RM) $(TARGET) $(TARGET)-bundle

$(TARGET): *.go go.mod docker
	docker run --rm -v $(CURDIR):/src -v $(HOME)/go:/go -w /src --user $(shell id -u):$(shell id -g) --env GOCACHE=/go/.cache ubuntu-ego ego-go build -o $@ .
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego sign $@
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego uniqueid $@

$(TARGET)-bundle: $(TARGET) docker
	docker run --rm -v $(CURDIR):/src -w /src --user $(shell id -u):$(shell id -g) ubuntu-ego ego bundle $<

.PHONY: docker

docker:
ifeq ($(shell docker images -q ubuntu-ego),)
	docker build -t ubuntu-ego .
endif
