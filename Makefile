CONTAINER_REGISTRY ?= ghcr.io/galleybytes
IMAGE_NAME ?= terraform-operator-plugin-manager
VERSION ?= $(shell  git describe --tags --dirty)
ifeq ($(VERSION),)
VERSION := 0.0.0
endif
IMG ?= ${CONTAINER_REGISTRY}/${IMAGE_NAME}:${VERSION}

ghactions-release:
	CGO_ENABLED=0 go build -v -o bin/manager main.go
	docker build . -t ${IMG}
	docker push ${IMG}

.PHONY: ghactions-release