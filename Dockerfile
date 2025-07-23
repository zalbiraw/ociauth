FROM golang:1.19-alpine AS builder

WORKDIR /app

COPY . .

# Build the main server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server

# Build the debug proxy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o debug-proxy ./cmd/debug-proxy

# Main server image
FROM alpine:latest AS server

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/server .

EXPOSE 8080

CMD ["./server"]

# Debug proxy image
FROM alpine:latest AS debug-proxy

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/debug-proxy .

EXPOSE 8080

CMD ["./debug-proxy"]