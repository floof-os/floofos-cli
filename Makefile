# FloofCTL Makefile
# Build automation for FloofOS Control CLI

# Variables
BINARY_NAME=floofctl
MAIN_PATH=./cmd/floofctl
BUILD_DIR=./bin
INSTALL_PATH=/usr/local/bin
CONFIG_PATH=/etc/floofos
SYSTEMD_PATH=/etc/systemd/system

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
GO_BUILD_FLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)"
GO_BUILD_ENV=CGO_ENABLED=0

# Targets
.PHONY: all build clean install uninstall test lint fmt vet deps dev run help

all: build

help:
	@echo "FloofCTL Build System"
	@echo "====================="
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build the floofctl binary"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install floofctl to system"
	@echo "  uninstall  - Remove floofctl from system"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linter"
	@echo "  fmt        - Format code"
	@echo "  vet        - Run go vet"
	@echo "  deps       - Download dependencies"
	@echo "  dev        - Build and run in development mode"
	@echo "  run        - Run floofctl without installing"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Build variables:"
	@echo "  VERSION    = $(VERSION)"
	@echo "  COMMIT     = $(COMMIT)"
	@echo "  BUILD_DATE = $(BUILD_DATE)"

build: deps
	@echo "Building floofctl..."
	@mkdir -p $(BUILD_DIR)
	$(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@go clean
	@echo "Clean complete"

install: build
	@echo "Installing floofctl..."
	
	# Create directories
	@sudo mkdir -p $(INSTALL_PATH)
	@sudo mkdir -p $(CONFIG_PATH)
	@sudo mkdir -p $(CONFIG_PATH)/templates
	@sudo mkdir -p $(CONFIG_PATH)/backups
	@sudo mkdir -p $(CONFIG_PATH)/generated
	@sudo mkdir -p /var/log/floofos
	
	# Install binary
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	
	# Install systemd service (if systemd is available)
	@if [ -d /etc/systemd/system ]; then \
		sudo cp scripts/floofctl.service $(SYSTEMD_PATH)/; \
		sudo systemctl daemon-reload; \
		echo "Systemd service installed"; \
	fi
	
	# Create symlinks for convenience
	@sudo ln -sf $(INSTALL_PATH)/$(BINARY_NAME) /usr/bin/$(BINARY_NAME) 2>/dev/null || true
	
	@echo "Installation complete"
	@echo "Run 'floofctl --help' to get started"

uninstall:
	@echo "Uninstalling floofctl..."
	
	# Stop and disable service if it exists
	@sudo systemctl stop floofctl 2>/dev/null || true
	@sudo systemctl disable floofctl 2>/dev/null || true
	
	# Remove files
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@sudo rm -f /usr/bin/$(BINARY_NAME)
	@sudo rm -f $(SYSTEMD_PATH)/floofctl.service
	
	# Remove config directory (with confirmation)
	@echo "Remove configuration directory $(CONFIG_PATH)? [y/N]"
	@read -r confirm && [ "$$confirm" = "y" ] && sudo rm -rf $(CONFIG_PATH) || echo "Configuration preserved"
	
	@sudo systemctl daemon-reload 2>/dev/null || true
	@echo "Uninstall complete"

test:
	@echo "Running tests..."
	@go test -v ./...

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

fmt:
	@echo "Formatting code..."
	@go fmt ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

dev: build
	@echo "Starting development server..."
	@$(BUILD_DIR)/$(BINARY_NAME) --shell

run: build
	@$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

# Development targets
.PHONY: build-linux build-windows build-darwin build-all

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)

build-all: build-linux build-windows build-darwin
	@echo "All platform builds complete"

# Docker targets
.PHONY: docker-build docker-run

docker-build:
	@echo "Building Docker image..."
	@docker build -t floofctl:$(VERSION) .

docker-run:
	@echo "Running Docker container..."
	@docker run -it --rm floofctl:$(VERSION)

# Release targets
.PHONY: release package

package: build-all
	@echo "Creating release packages..."
	@mkdir -p $(BUILD_DIR)/packages
	
	# Linux package
	@tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64
	
	# Windows package
	@zip -j $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe
	
	# macOS package
	@tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64
	
	@echo "Packages created in $(BUILD_DIR)/packages/"

release: clean test lint package
	@echo "Release $(VERSION) ready"
	@ls -la $(BUILD_DIR)/packages/

# Maintenance targets
.PHONY: update-deps check-deps security-scan

update-deps:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

check-deps:
	@echo "Checking for outdated dependencies..."
	@go list -u -m all

security-scan:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Setup targets for development
.PHONY: setup-dev install-tools

setup-dev: install-tools deps
	@echo "Development environment setup complete"

install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "Tools installed"