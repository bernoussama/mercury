# syntax=docker/dockerfile:1

# Build the application from source
FROM golang:1.23 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY *.go ./
COPY cmd/ cmd/
COPY dns/ dns/
COPY cache/ cache/

RUN CGO_ENABLED=0 GOOS=linux go build -o /mercury

# Run the tests in the container
FROM build-stage AS run-test-stage
RUN go test -v ./...

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

COPY --from=build-stage /mercury /mercury

EXPOSE 53/udp
EXPOSE 53/tcp

USER nonroot:nonroot

ENTRYPOINT ["/mercury", "serve"]
