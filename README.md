````markdown
# Strava Heatmap Envoy

A simple, lightweight proxy server that provides access to Strava's global heatmap tiles. It handles the authentication and cookie refresh process, allowing you to integrate Strava's heatmap into your mapping applications.

## Overview

This application runs as a server that fetches heatmap tiles from Strava on your behalf. It manages the required authentication cookies and automatically refreshes them when they expire. It serves tiles over standard HTTP and can be configured to use HTTPS.

The primary goal is to provide a stable tile endpoint, like `http://localhost:8080/all/blue/{z}/{x}/{y}.png`, which can be used in map clients like Leaflet, OpenLayers, or GIS software (JOSM).

## Usage

There are two primary ways to run this application: using Docker or running a pre-compiled binary.

### 1. Docker

**Steps:**

1.  **Get your Strava Session Cookie (Recommended):**
    *   Log in to the [Strava website](https://www.strava.com).
    *   Open your browser's developer tools (usually by pressing F12).
    *   Go to the "Application" (or "Storage") tab, find the cookies for `www.strava.com`, and copy the value of the `_strava4_session` cookie.

2.  **Run the container:**
    The image will be pulled automatically from [GitHub Container Registry](https://github.com/lumixen?tab=packages&repo_name=strava-heatmap-envoy). Replace `<your_strava_session_cookie>` with the value you copied.

    ```sh
    docker run -d \
      -p 8080:8080 \
      -e STRAVA_SESSION_COOKIE="<your_strava_session_cookie>" \
      --name strava-proxy \
      ghcr.io/lumixen/strava-heatmap-envoy:latest
    ```

### 2. Local Binaries

Pre-compiled binaries for Linux, Windows, and macOS are created by the build script in the `build/artifacts/` directory.

**Steps:**

1.  **Download the appropriate binary** for your operating system and architecture from the project's releases.

2.  **Get your Strava Session Cookie** as described in the Docker instructions.

3.  **Run the binary from your terminal:**

    *   **Linux / macOS:**
        ```sh
        export STRAVA_SESSION_COOKIE="<your_strava_session_cookie>"
        ./strava-heatmap-envoy
        ```

    *   **Windows (Command Prompt):**
        ```cmd
        set STRAVA_SESSION_COOKIE="<your_strava_session_cookie>"
        strava-heatmap-envoy.exe
        ```

### Tile Server URL

Once running, you can access the heatmap tiles at the following URL:

`http://localhost:8080/{activity}/{color}/{z}/{x}/{y}.png`

Example: `http://localhost:8080/all/blue/10/512/341.png`

## Configuration

The application is configured using environment variables:

| Variable                | Description                                                                                             | Default | Required |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | ------- | -------- |
| `STRAVA_SESSION_COOKIE` | Your `_strava4_session` cookie value from strava.com. If not set, a hardcoded fallback is used.           |         | No       |
| `HTTP_PORT`             | The port for the HTTP server.                                                                           | `8080`  | No       |
| `HTTPS_PORT`            | The port for the HTTPS server.                                                                          | `8443`  | No       |
| `CERT_PEM`              | Path to the SSL certificate file (`.pem` or `.crt`). Enables HTTPS if set along with `KEY_PEM`.           |         | No       |
| `KEY_PEM`               | Path to the SSL private key file (`.pem` or `.key`). Enables HTTPS if set along with `CERT_PEM`.          |         | No       |
| `LOG_DEBUG`             | Set to `1` or `true` to enable verbose logging of served tiles.                                         | `false` | No       |
 |

## Building from Source

To build the project yourself, you need Go installed.

1.  **Build a single binary:**
    ```sh
    go build .
    ```

2.  **Build for all target platforms:**
    The [scripts/build.sh](scripts/build.sh) script cross-compiles binaries for multiple platforms and places them in the `build/artifacts` directory.
    ```sh
    ./scripts/build.sh
    ```