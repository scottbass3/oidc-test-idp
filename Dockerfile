# Build stage: produce a static, cgo-free binary.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp
# Prepare the data directory so it can be copied with nonroot ownership below.
RUN mkdir -p /data

# Runtime stage: distroless, no shell, minimal surface.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/idp /idp
# Data directory owned by the nonroot user (uid/gid 65532). A named volume
# mounted here inherits this ownership, so SQLite can create /data/idp.db.
COPY --from=build --chown=65532:65532 /data /data
# Config volume holds the SQLite database (persisted inside the container/volume).
VOLUME ["/data"]
EXPOSE 9000
ENV IDP_ADDR=:9000 \
    IDP_ISSUER=http://localhost:9000 \
    IDP_DB_PATH=/data/idp.db
USER nonroot:nonroot
ENTRYPOINT ["/idp"]
