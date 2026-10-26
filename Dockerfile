FROM golang:1.26.4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/grafana-linkkeys-login ./cmd/grafana-linkkeys-login

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/grafana-linkkeys-login /usr/local/bin/grafana-linkkeys-login
USER nonroot
ENTRYPOINT ["/usr/local/bin/grafana-linkkeys-login"]
CMD ["serve", "-config", "/config/config.yaml"]
