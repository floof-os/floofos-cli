#!/bin/bash
# FloofCTL Build Script
# Automated build script for FloofOS Control CLI

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="floofctl"
BUILD_DIR="$PROJECT_ROOT/bin"

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

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        log_info "Please install Go from https://golang.org/dl/"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $GO_VERSION"
}

# Check if required tools are available
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for git (for version info)
    if command -v git &> /dev/null; then
        GIT_AVAILABLE=true
    else
        GIT_AVAILABLE=false
        log_warning "Git not found - version info will be limited"
    fi
    
    # Check for make
    if command -v make &> /dev/null; then
        MAKE_AVAILABLE=true
        log_info "Make is available"
    else
        MAKE_AVAILABLE=false
        log_warning "Make not found - using direct go build"
    fi
}

# Get version information
get_version_info() {
    if [ "$GIT_AVAILABLE" = true ]; then
        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
        COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    else
        VERSION="dev"
        COMMIT="unknown"
    fi
    
    BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    log_info "Version: $VERSION"
    log_info "Commit: $COMMIT"
    log_info "Build Date: $BUILD_DATE"
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
}

# Download dependencies
download_deps() {
    log_info "Downloading dependencies..."
    cd "$PROJECT_ROOT"
    
    if [ ! -f "go.mod" ]; then
        log_error "go.mod not found. Are you in the correct directory?"
        exit 1
    fi
    
    go mod download
    go mod tidy
    log_success "Dependencies downloaded"
}

# Build the binary
build_binary() {
    log_info "Building $BINARY_NAME..."
    cd "$PROJECT_ROOT"
    
    # Build flags
    BUILD_FLAGS="-ldflags \"-X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$BUILD_DATE\""
    
    # Build command
    if [ "$MAKE_AVAILABLE" = true ]; then
        make build
    else
        # Direct go build
        CGO_ENABLED=0 go build $BUILD_FLAGS -o "$BUILD_DIR/$BINARY_NAME" "./cmd/floofctl"
    fi
    
    if [ -f "$BUILD_DIR/$BINARY_NAME" ]; then
        log_success "Build completed: $BUILD_DIR/$BINARY_NAME"
        
        # Show binary info
        BINARY_SIZE=$(du -h "$BUILD_DIR/$BINARY_NAME" | cut -f1)
        log_info "Binary size: $BINARY_SIZE"
        
        # Test binary
        if "$BUILD_DIR/$BINARY_NAME" --version &> /dev/null; then
            log_success "Binary test passed"
        else
            log_warning "Binary test failed - but build completed"
        fi
    else
        log_error "Build failed - binary not found"
        exit 1
    fi
}

# Build for multiple platforms
build_cross_platform() {
    log_info "Building for multiple platforms..."
    cd "$PROJECT_ROOT"
    
    # Platforms to build for
    PLATFORMS=(
        "linux/amd64"
        "linux/arm64"
        "windows/amd64"
        "darwin/amd64"
        "darwin/arm64"
    )
    
    for PLATFORM in "${PLATFORMS[@]}"; do
        GOOS=${PLATFORM%/*}
        GOARCH=${PLATFORM#*/}
        
        OUTPUT_NAME="$BINARY_NAME-$GOOS-$GOARCH"
        if [ "$GOOS" = "windows" ]; then
            OUTPUT_NAME="$OUTPUT_NAME.exe"
        fi
        
        log_info "Building for $GOOS/$GOARCH..."
        
        CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
            -ldflags "-X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$BUILD_DATE" \
            -o "$BUILD_DIR/$OUTPUT_NAME" \
            "./cmd/floofctl"
        
        if [ -f "$BUILD_DIR/$OUTPUT_NAME" ]; then
            BINARY_SIZE=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
            log_success "✓ $GOOS/$GOARCH ($BINARY_SIZE)"
        else
            log_error "✗ $GOOS/$GOARCH (failed)"
        fi
    done
}

# Run tests
run_tests() {
    log_info "Running tests..."
    cd "$PROJECT_ROOT"
    
    if go test -v ./...; then
        log_success "All tests passed"
    else
        log_warning "Some tests failed"
        return 1
    fi
}

# Package the build
create_package() {
    log_info "Creating release package..."
    cd "$BUILD_DIR"
    
    # Create archive
    ARCHIVE_NAME="${BINARY_NAME}-${VERSION}"
    
    if command -v tar &> /dev/null; then
        tar -czf "${ARCHIVE_NAME}.tar.gz" "$BINARY_NAME"
        log_success "Package created: ${ARCHIVE_NAME}.tar.gz"
    else
        log_warning "tar not available - skipping package creation"
    fi
}

# Show usage
show_usage() {
    echo "FloofCTL Build Script"
    echo "===================="
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -c, --clean         Clean build directory before building"
    echo "  -t, --test          Run tests before building"
    echo "  -x, --cross         Build for multiple platforms"
    echo "  -p, --package       Create release package"
    echo "  -a, --all           Clean, test, build cross-platform, and package"
    echo "  -v, --verbose       Verbose output"
    echo ""
    echo "Examples:"
    echo "  $0                  # Simple build"
    echo "  $0 --clean --test   # Clean and test before build"
    echo "  $0 --all            # Full release build"
}

# Main script
main() {
    local CLEAN_BUILD=false
    local RUN_TESTS=false
    local CROSS_PLATFORM=false
    local CREATE_PACKAGE=false
    local VERBOSE=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--clean)
                CLEAN_BUILD=true
                shift
                ;;
            -t|--test)
                RUN_TESTS=true
                shift
                ;;
            -x|--cross)
                CROSS_PLATFORM=true
                shift
                ;;
            -p|--package)
                CREATE_PACKAGE=true
                shift
                ;;
            -a|--all)
                CLEAN_BUILD=true
                RUN_TESTS=true
                CROSS_PLATFORM=true
                CREATE_PACKAGE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                set -x
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
    echo "FloofCTL Build Script"
    echo "===================="
    echo ""
    
    # Run build steps
    check_go
    check_dependencies
    get_version_info
    
    if [ "$CLEAN_BUILD" = true ]; then
        clean_build
    else
        mkdir -p "$BUILD_DIR"
    fi
    
    download_deps
    
    if [ "$RUN_TESTS" = true ]; then
        if ! run_tests; then
            log_error "Tests failed - aborting build"
            exit 1
        fi
    fi
    
    if [ "$CROSS_PLATFORM" = true ]; then
        build_cross_platform
    else
        build_binary
    fi
    
    if [ "$CREATE_PACKAGE" = true ]; then
        create_package
    fi
    
    echo ""
    log_success "Build process completed!"
    echo ""
    echo "Built files:"
    ls -la "$BUILD_DIR"
    echo ""
    log_info "To install: make install"
    log_info "To run: $BUILD_DIR/$BINARY_NAME"
}

# Run main function with all arguments
main "$@"