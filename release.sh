#!/bin/bash -xe
dir="$(dirname $0)"
cd "$dir"
repo=${repo:-ghcr.io/galleybytes/terraform-operator-plugin-manager}
tag=$(git describe --tags --dirty||true)
tag=${tag:-0.0.0}
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o bin/manager main.go
docker build . -t "$repo:$tag"
if [[ "$RELEASE_PROJECT" == true ]]; then
  docker push "$repo:$tag"
fi
if [[ "$RELEASE_KIND" == true ]]; then
  # Load into my kind cluster for testing
  kind load docker-image "$repo:$tag"
fi
