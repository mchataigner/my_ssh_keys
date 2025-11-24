.PHONY: build clean install test run

# Build the binary
build:
	go build -o fetch_ssh_keys

# Build with optimizations for release
release:
	go build -ldflags="-s -w" -o fetch_ssh_keys

# Clean build artifacts
clean:
	rm -f fetch_ssh_keys

# Install to GOBIN
install:
	go install

# Run tests
test:
	go test -v ./...

# Run the program (example)
run:
	go run main.go github torvalds

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Download dependencies
deps:
	go mod download
	go mod tidy
