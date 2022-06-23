FROM golang:latest AS builder

# Set necessary environment variables needed for our image
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Move to working directory /build
WORKDIR /build

RUN apt-get update && apt-get install -y ca-certificates openssl

ARG cert_location=/usr/local/share/ca-certificates

# Get certificate from "github.com"
RUN openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > ${cert_location}/github.crt
# Get certificate from "proxy.golang.org"
RUN openssl s_client -showcerts -connect proxy.golang.org:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >  ${cert_location}/proxy.golang.crt
# Update certificates
RUN update-ca-certificates

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY *.go .

# Build the application
RUN go build -o main .

# Move to /dist directory as the place for resulting binary folder
WORKDIR /dist

# Copy binary from build to main folder
RUN cp /build/main .

# Build a small image
FROM scratch

# scratch doesn't have the standard SSL certs that this service needs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /dist/main /

# Export necessary port
EXPOSE 5000

# Command to run
ENTRYPOINT ["/main"]
