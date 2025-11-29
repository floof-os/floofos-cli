#!/bin/bash
# FloofCTL Installation Script
# System installation script for FloofOS Control CLI

set -e

# Configuration
BINARY_NAME="floofctl"
INSTALL_PATH="/usr/local/bin"
CONFIG_PATH="/etc/floofos"
SYSTEMD_PATH="/etc/systemd/system"
LOG_PATH="/var/log/floofos"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root or with sudo
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        log_info "Please run: sudo $0"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    log_info "Checking system compatibility..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        log_info "Operating System: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="darwin"
        log_info "Operating System: macOS"
        log_warning "macOS support is experimental"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "Architecture: $ARCH"
    
    # Check for systemd (Linux only)
    if [[ "$OS" == "linux" ]]; then
        if command -v systemctl &> /dev/null; then
            SYSTEMD_AVAILABLE=true
            log_info "Systemd: Available"
        else
            SYSTEMD_AVAILABLE=false
            log_warning "Systemd: Not available"
        fi
    else
        SYSTEMD_AVAILABLE=false
    fi
}

# Download latest release
download_binary() {
    log_info "Downloading latest release..."
    
    # GitHub release URL (adjust as needed)
    GITHUB_REPO="floofos/floofctl"
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    
    if [[ "$OS" == "windows" ]]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
    fi
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    TEMP_BINARY="$TEMP_DIR/$BINARY_NAME"
    
    log_info "Downloading from: $DOWNLOAD_URL"
    
    # Download binary
    if command -v curl &> /dev/null; then
        if curl -L -o "$TEMP_BINARY" "$DOWNLOAD_URL"; then
            log_success "Download completed"
        else
            log_error "Download failed with curl"
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if wget -O "$TEMP_BINARY" "$DOWNLOAD_URL"; then
            log_success "Download completed"
        else
            log_error "Download failed with wget"
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    else
        log_error "Neither curl nor wget is available for downloading"
        log_info "Please install curl or wget, or download manually from:"
        log_info "$DOWNLOAD_URL"
        exit 1
    fi
    
    # Verify download
    if [[ ! -f "$TEMP_BINARY" ]]; then
        log_error "Downloaded binary not found"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # Make executable
    chmod +x "$TEMP_BINARY"
    
    # Test binary
    if "$TEMP_BINARY" --version &> /dev/null; then
        log_success "Binary verification passed"
    else
        log_warning "Binary verification failed, but continuing..."
    fi
    
    DOWNLOADED_BINARY="$TEMP_BINARY"
}

# Install from local binary
install_local() {
    local LOCAL_BINARY="$1"
    
    if [[ ! -f "$LOCAL_BINARY" ]]; then
        log_error "Local binary not found: $LOCAL_BINARY"
        exit 1
    fi
    
    if [[ ! -x "$LOCAL_BINARY" ]]; then
        log_error "Local binary is not executable: $LOCAL_BINARY"
        exit 1
    fi
    
    DOWNLOADED_BINARY="$LOCAL_BINARY"
    log_info "Using local binary: $LOCAL_BINARY"
}

# Create system directories
create_directories() {
    log_info "Creating system directories..."
    
    # Main directories
    mkdir -p "$INSTALL_PATH"
    mkdir -p "$CONFIG_PATH"
    mkdir -p "$CONFIG_PATH/templates"
    mkdir -p "$CONFIG_PATH/backups"
    mkdir -p "$CONFIG_PATH/generated"
    mkdir -p "$CONFIG_PATH/generated/scripts"
    mkdir -p "$CONFIG_PATH/generated/keys"
    mkdir -p "$LOG_PATH"
    
    # Set permissions
    chmod 755 "$INSTALL_PATH"
    chmod 755 "$CONFIG_PATH"
    chmod 700 "$CONFIG_PATH/generated/keys"  # Restrictive for keys
    chmod 755 "$LOG_PATH"
    
    log_success "Directories created"
}

# Install binary
install_binary() {
    log_info "Installing binary..."
    
    # Copy binary
    cp "$DOWNLOADED_BINARY" "$INSTALL_PATH/$BINARY_NAME"
    chmod +x "$INSTALL_PATH/$BINARY_NAME"
    
    # Create symlink in /usr/bin if it doesn't exist
    if [[ ! -f "/usr/bin/$BINARY_NAME" ]]; then
        ln -sf "$INSTALL_PATH/$BINARY_NAME" "/usr/bin/$BINARY_NAME"
    fi
    
    log_success "Binary installed to $INSTALL_PATH/$BINARY_NAME"
}

# Create systemd service
create_systemd_service() {
    if [[ "$SYSTEMD_AVAILABLE" != true ]]; then
        log_info "Skipping systemd service creation (not available)"
        return
    fi
    
    log_info "Creating systemd service..."
    
    cat > "$SYSTEMD_PATH/floofctl.service" << EOF
[Unit]
Description=FloofOS Control CLI Service
Documentation=https://github.com/floofos/floofctl
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_PATH/$BINARY_NAME --shell
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=floofctl

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_PATH $LOG_PATH

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd service created"
    log_info "To enable: systemctl enable floofctl"
    log_info "To start: systemctl start floofctl"
}

# Create default configuration
create_default_config() {
    log_info "Creating default configuration..."
    
    cat > "$CONFIG_PATH/floofos.yaml" << EOF
# FloofOS Configuration
# Generated by installation script

version: "1.0"
system:
  hostname: "floofos-router"
  domain: "local"
  timezone: "UTC"

services:
  vpp:
    enabled: true
    config_path: "/etc/vpp/startup.conf"
  bird:
    enabled: true
    config_path: "/etc/bird/bird.conf"
  pathvector:
    enabled: false
    config_path: "/etc/pathvector/pathvector.yml"

logging:
  level: "info"
  file: "$LOG_PATH/floofos.log"
  max_size: "10MB"
  max_backups: 5

backup:
  auto_backup: true
  retention_days: 30
  compression: true
EOF
    
    chmod 644 "$CONFIG_PATH/floofos.yaml"
    log_success "Default configuration created"
}

# Set up logging
setup_logging() {
    log_info "Setting up logging..."
    
    # Create logrotate configuration
    if command -v logrotate &> /dev/null; then
        cat > "/etc/logrotate.d/floofos" << EOF
$LOG_PATH/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
        log_success "Log rotation configured"
    else
        log_warning "logrotate not available - manual log management required"
    fi
}

# Post-installation setup
post_install() {
    log_info "Performing post-installation setup..."
    
    # Test installation
    if "$INSTALL_PATH/$BINARY_NAME" --version &> /dev/null; then
        VERSION=$("$INSTALL_PATH/$BINARY_NAME" --version | head -n1)
        log_success "Installation verified: $VERSION"
    else
        log_warning "Installation verification failed"
    fi
    
    # Show service status if available
    if [[ "$SYSTEMD_AVAILABLE" == true ]]; then
        if systemctl is-enabled floofctl &> /dev/null; then
            log_info "Service status: $(systemctl is-active floofctl)"
        fi
    fi
}

# Cleanup temporary files
cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_info "Temporary files cleaned up"
    fi
}

# Show installation summary
show_summary() {
    echo ""
    log_success "FloofCTL installation completed!"
    echo ""
    echo "Installation Summary:"
    echo "===================="
    echo "Binary: $INSTALL_PATH/$BINARY_NAME"
    echo "Config: $CONFIG_PATH/"
    echo "Logs: $LOG_PATH/"
    if [[ "$SYSTEMD_AVAILABLE" == true ]]; then
        echo "Service: systemctl {start|stop|status} floofctl"
    fi
    echo ""
    echo "Quick Start:"
    echo "============"
    echo "# Show help"
    echo "$BINARY_NAME --help"
    echo ""
    echo "# Start interactive shell"
    echo "$BINARY_NAME"
    echo ""
    echo "# Show status"
    echo "$BINARY_NAME status"
    echo ""
    if [[ "$SYSTEMD_AVAILABLE" == true ]]; then
        echo "# Enable service"
        echo "systemctl enable floofctl"
        echo "systemctl start floofctl"
        echo ""
    fi
}

# Show usage
show_usage() {
    echo "FloofCTL Installation Script"
    echo "============================"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -l, --local PATH    Install from local binary"
    echo "  -f, --force         Force installation (overwrite existing)"
    echo "  -n, --no-service    Skip systemd service creation"
    echo "  -d, --download-only Download binary only (don't install)"
    echo ""
    echo "Examples:"
    echo "  sudo $0                      # Install latest release"
    echo "  sudo $0 --local ./floofctl   # Install from local binary"
    echo "  sudo $0 --no-service         # Install without systemd service"
}

# Main installation function
main() {
    local LOCAL_BINARY=""
    local FORCE_INSTALL=false
    local SKIP_SERVICE=false
    local DOWNLOAD_ONLY=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -l|--local)
                LOCAL_BINARY="$2"
                shift 2
                ;;
            -f|--force)
                FORCE_INSTALL=true
                shift
                ;;
            -n|--no-service)
                SKIP_SERVICE=true
                shift
                ;;
            -d|--download-only)
                DOWNLOAD_ONLY=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Show banner
    echo "FloofCTL Installation Script"
    echo "============================"
    echo ""
    
    # Trap for cleanup
    trap cleanup EXIT
    
    # Check prerequisites
    check_privileges
    check_system
    
    # Check for existing installation
    if [[ -f "$INSTALL_PATH/$BINARY_NAME" && "$FORCE_INSTALL" != true ]]; then
        EXISTING_VERSION=$("$INSTALL_PATH/$BINARY_NAME" --version 2>/dev/null | head -n1 || echo "unknown")
        log_warning "FloofCTL is already installed: $EXISTING_VERSION"
        log_info "Use --force to overwrite existing installation"
        exit 1
    fi
    
    # Get binary
    if [[ -n "$LOCAL_BINARY" ]]; then
        install_local "$LOCAL_BINARY"
    else
        download_binary
    fi
    
    # Download only mode
    if [[ "$DOWNLOAD_ONLY" == true ]]; then
        log_info "Download completed: $DOWNLOADED_BINARY"
        exit 0
    fi
    
    # Install
    create_directories
    install_binary
    create_default_config
    setup_logging
    
    # Create systemd service
    if [[ "$SKIP_SERVICE" != true ]]; then
        create_systemd_service
    fi
    
    # Post-installation
    post_install
    
    # Show summary
    show_summary
}

# Run main function with all arguments
main "$@"