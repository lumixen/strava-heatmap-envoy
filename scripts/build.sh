#!/bin/bash

APP_NAME="strava-heatmap-envoy"
PLATFORMS=("linux/amd64" "linux/arm64" "linux/arm" "windows/amd64" "darwin/amd64" "darwin/arm64")
BUILD_DIR="build"

# Get current Git tag or short SHA if no tag
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null)
if [ -z "$GIT_TAG" ]; then
    GIT_TAG=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
fi
echo "Building version: $GIT_TAG"

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/artifacts

for PLATFORM in "${PLATFORMS[@]}"; do
    OS=${PLATFORM%/*}
    ARCH=${PLATFORM#*/}
    PLATFORM_DIR="$BUILD_DIR/$APP_NAME-$OS-$ARCH"

    mkdir -p "$PLATFORM_DIR"
    OUTPUT="$PLATFORM_DIR/$APP_NAME"

    # Add .exe extension for Windows builds
    if [ "$OS" == "windows" ]; then
        OUTPUT+=".exe"
    fi

    echo "🚀 Building for $OS/$ARCH..."
    env GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o "$OUTPUT" .

    if [ $? -ne 0 ]; then
        echo "❌ Failed to build for $OS/$ARCH"
        exit 1
    else
        echo "✅ Built: $OUTPUT"
    fi

    if [ "$OS" != "darwin" ]; then
        echo "Compressing binary with UPX..."
        upx --best "$OUTPUT"
        if [ $? -ne 0 ]; then
            echo "❌ UPX compression failed for $OUTPUT"
        else
            echo "Compressed: $OUTPUT"
        fi
    else
        echo "⏩ Skipping UPX for $OS/$ARCH"
    fi

    # Create a ZIP archive with the Git tag
    ZIP_NAME="$BUILD_DIR/artifacts/$APP_NAME-${OS}-${ARCH}-${GIT_TAG}.zip"
    zip -j "$ZIP_NAME" "$OUTPUT"

    if [ $? -ne 0 ]; then
        echo "❌ Failed to create ZIP: $ZIP_NAME"
        exit 1
    else
        echo "✅ Created ZIP archive: $ZIP_NAME"
    fi
done