ARG GOLANG_VERSION=1.25
ARG PLUGIN_NAME=vault-plugin-dynatrace-feature-management
ARG BUILD_VERSION=dev

FROM golang:${GOLANG_VERSION} AS builder
ARG PLUGIN_NAME
ARG BUILD_VERSION
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${BUILD_VERSION}" \
    -o /out/${PLUGIN_NAME} ./cmd/${PLUGIN_NAME} && \
    sha256sum /out/${PLUGIN_NAME} | cut -d' ' -f1 > /out/${PLUGIN_NAME}.sha256sum

FROM gcr.io/distroless/static:debug-nonroot AS cp-provider

FROM gcr.io/distroless/static:nonroot
ARG PLUGIN_NAME=vault-plugin-dynatrace-feature-management
LABEL org.opencontainers.image.source="https://github.com/Dynatrace/feature-management-vault-plugin"
LABEL org.opencontainers.image.description="HashiCorp Vault secrets-engine plugin for Dynatrace Feature Management"
WORKDIR /
COPY --from=builder /out/${PLUGIN_NAME} /vault-plugin-dynatrace-feature-management
COPY --from=builder /out/${PLUGIN_NAME}.sha256sum /vault-plugin-dynatrace-feature-management.sha256sum
COPY --from=cp-provider /busybox/cp /busybox/
ENTRYPOINT ["/vault-plugin-dynatrace-feature-management"]
