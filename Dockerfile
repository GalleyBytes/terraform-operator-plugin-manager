FROM scratch
COPY bin/manager /manager
ENTRYPOINT ["/manager"]
LABEL org.opencontainers.image.source https://github.com/galleybytes/terraform-operator-plugin-manager
