# Build stage
FROM golang:1.20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o ares-c2 .

# Final stage
FROM alpine:3.17

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Create non-root user
RUN addgroup -S ares && adduser -S ares -G ares

# Copy binary from builder
COPY --from=builder /app/ares-c2 .
COPY --from=builder /app/config.yaml .

# Create necessary directories
RUN mkdir -p /app/uploads /app/ssl && \
    chown -R ares:ares /app

# Switch to non-root user
USER ares

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

# Run the application
ENTRYPOINT ["./ares-c2"]
