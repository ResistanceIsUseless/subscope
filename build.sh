#!/bin/bash

# Build script for SubScope with version injection
# Usage: ./build.sh [version]

set -e

# Get version from argument or VERSION file
if [ -n "$1" ]; then
    VERSION="$1"
elif [ -f "VERSION" ]; then
    VERSION=$(cat VERSION)
else
    VERSION="dev"
fi

# Get build info
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags for version injection
LDFLAGS="-X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.GitCommit=${GIT_COMMIT}"

echo "Building SubScope version ${VERSION}"
echo "Build date: ${BUILD_DATE}"
echo "Git commit: ${GIT_COMMIT}"

# Build for current platform
go build -ldflags "${LDFLAGS}" -o subscope cmd/subscope/*.go

echo "Build completed: ./subscope"
echo "Test version: ./subscope --version"