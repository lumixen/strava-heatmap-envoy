package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/image/draw"
	"golang.org/x/net/http2"
)

var debugEnabled bool
var scalingEnabled bool

// Global state for cookies, protected by a mutex
var (
	cookies     []*http.Cookie
	cookiesLock sync.RWMutex
	lastFetch   time.Time
)

// Global map for persistent HTTP/2 clients
var (
	httpClients = make(map[string]*http.Client)
	clientsLock sync.Mutex
)

var tilePathRegex = regexp.MustCompile(`/([^/]+)/([^/]+)/(\d+)/(\d+)/(\d+)\.png`)

var tileCache *expirable.LRU[string, image.Image]
var notFoundCache *expirable.LRU[string, bool]

func init() {
	tileCache = expirable.NewLRU[string, image.Image](150, nil, 1*time.Hour)
	// Cache for paths that are known to not exist.
	notFoundCache = expirable.NewLRU[string, bool](40000, nil, 1*time.Hour)
}

// getHttpClient returns a persistent HTTP client for a given host.
// It creates a new client if one doesn't exist for the host.
func getHttpClient(host string) *http.Client {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	// If a client for the host already exists, return it.
	if client, ok := httpClients[host]; ok {
		return client
	}

	// Create a new transport that is configured to prefer HTTP/2.
	tr := &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial(network, addr, cfg)
		},
	}

	client := &http.Client{
		Transport: tr,
	}

	log.Printf("Created new persistent HTTP/2 client for %s", host)
	httpClients[host] = client
	return client
}

// parseTilePath extracts zoom, x, and y from a URL path.
func parseTilePath(path string) (sport, color string, z, x, y int, ok bool) {
	matches := tilePathRegex.FindStringSubmatch(path)
	if len(matches) != 6 {
		return "", "", 0, 0, 0, false
	}

	sport = matches[1]
	color = matches[2]
	z, errZ := strconv.Atoi(matches[3])
	x, errX := strconv.Atoi(matches[4])
	y, errY := strconv.Atoi(matches[5])

	if errZ != nil || errX != nil || errY != nil {
		return "", "", 0, 0, 0, false
	}

	return sport, color, z, x, y, true
}

// getCookies fetches authentication cookies from Strava.
// It includes a simple rate limit to avoid fetching too frequently.
func getCookies() {
	cookiesLock.Lock()
	// Rate limit to once every 4 minutes
	if time.Since(lastFetch) < 4*time.Minute {
		cookiesLock.Unlock()
		return
	}
	lastFetch = time.Now()
	cookiesLock.Unlock()

	log.Println("Reading cookies from Strava...")

	req, err := http.NewRequest("GET", "https://www.strava.com/maps/global-heatmap?sport=All&style=dark&terrain=false&labels=true&poi=true&cPhotos=true&gColor=blue&gOpacity=100", nil)
	if err != nil {
		log.Printf("Error creating request to get cookies: %v", err)
		return
	}

	stravaSessionCookie := os.Getenv("STRAVA_SESSION_COOKIE")
	if stravaSessionCookie == "" {
		stravaSessionCookie = "eier68hdchci83gf4kb0pre1inqnqvdt"
		log.Println("STRAVA_SESSION_COOKIE environment variable not set, using default fallback.")
	}

	// Add the initial session cookie needed for authentication
	req.AddCookie(&http.Cookie{
		Name:  "_strava4_session",
		Value: stravaSessionCookie,
	})

	client := getHttpClient("www.strava.com")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching cookies: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Invalid response status when fetching cookies: %s", resp.Status)
		return
	}

	cookiesLock.Lock()
	cookies = resp.Cookies()
	cookiesLock.Unlock()

	log.Println("Cookies read successfully.")
}

// tileProxyHandler handles incoming tile requests.
func tileProxyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	targetURL := "https://content-a.strava.com/identified/globalheat" + r.URL.Path

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Printf("Error creating tile request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Add the fetched cookies to the request
	cookiesLock.RLock()
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	cookiesLock.RUnlock()

	client := getHttpClient("content-a.strava.com")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching tile: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// If access is forbidden, our cookies are likely stale. Refresh them.
	if resp.StatusCode == http.StatusForbidden {
		log.Println("Received 403 Forbidden, refreshing cookies.")
		go getCookies() // Refresh in the background
		http.Error(w, "Forbidden - try again shortly", http.StatusForbidden)
		return
	}

	if resp.StatusCode == http.StatusNotFound {
		if !scalingEnabled {
			http.NotFound(w, r)
			return
		}

		sport, color, requestedZ, requestedX, requestedY, ok := parseTilePath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}

		var parentImg image.Image
		var foundZ int

		// Iteratively search for an available parent tile, going up zoom levels
		for z := requestedZ - 1; z >= 0; z-- {
			x := requestedX / (1 << (requestedZ - z))
			y := requestedY / (1 << (requestedZ - z))

			parentPath := fmt.Sprintf("/%s/%s/%d/%d/%d.png", sport, color, z, x, y)

			// Check not-found cache first
			if _, found := notFoundCache.Get(parentPath); found {
				if debugEnabled {
					log.Printf("Skipping known not-found tile: %s", parentPath)
				}
				continue // Skip this path, we know it doesn't exist
			}

			// Check cache first
			if cachedImg, found := tileCache.Get(parentPath); found {
				if debugEnabled {
					log.Printf("Found cached ancestor tile at %s", parentPath)
				}
				parentImg = cachedImg
				foundZ = z
				break // Found in cache, exit loop
			}

			parentTargetURL := "https://content-a.strava.com/identified/globalheat" + parentPath
			if debugEnabled {
				log.Printf("Attempting to find parent tile at zoom %d: %s", z, parentPath)
			}

			parentReq, _ := http.NewRequest("GET", parentTargetURL, nil)
			cookiesLock.RLock()
			for _, cookie := range cookies {
				parentReq.AddCookie(cookie)
			}
			cookiesLock.RUnlock()

			parentResp, err := client.Do(parentReq)
			if err != nil {
				log.Printf("Error fetching parent tile %s: %v", parentPath, err)
				continue // Try the next level up
			}

			if parentResp.StatusCode == http.StatusNotFound {
				// Add to the not-found cache and continue to the next zoom level
				notFoundCache.Add(parentPath, true)
				parentResp.Body.Close()
				continue
			}

			if parentResp.StatusCode == http.StatusOK {
				img, err := png.Decode(parentResp.Body)
				parentResp.Body.Close()
				if err != nil {
					log.Printf("Error decoding parent tile %s: %v", parentPath, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				parentImg = img
				foundZ = z

				// Add the newly fetched tile to the cache
				tileCache.Add(parentPath, img)

				if debugEnabled {
					log.Printf("Found available ancestor tile at %s", parentPath)
				}
				break // Found a valid tile, exit loop
			}
			parentResp.Body.Close()
		}

		if parentImg == nil {
			log.Printf("No ancestor tile found for %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		// We have the ancestor tile (parentImg at foundZ), now we need to scale it up.
		// This is more efficient than scaling one zoom level at a time.
		deltaZ := requestedZ - foundZ
		scaleFactor := 1 << deltaZ

		// Calculate the coordinates of the requested tile within the ancestor tile's grid.
		innerX := requestedX % scaleFactor
		innerY := requestedY % scaleFactor

		// Calculate the size of the sub-tile area in the parent image.
		subTileSize := 512 / scaleFactor

		// Define the source rectangle in the parent image.
		srcRect := image.Rect(
			innerX*subTileSize,
			innerY*subTileSize,
			(innerX+1)*subTileSize,
			(innerY+1)*subTileSize,
		)

		srcQuadrant := parentImg.(interface {
			SubImage(r image.Rectangle) image.Image
		}).SubImage(srcRect)

		// The destination is a new 512x512 tile.
		newTile := image.NewRGBA(image.Rect(0, 0, 512, 512))
		// Scale the source rectangle directly to the full size of the new tile.
		draw.CatmullRom.Scale(newTile, newTile.Bounds(), srcQuadrant, srcQuadrant.Bounds(), draw.Over, nil)

		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		if err := png.Encode(w, newTile); err != nil {
			log.Printf("Error encoding scaled tile: %v", err)
		}
		if debugEnabled {
			log.Printf("Served scaled tile for: %s from ancestor at zoom %d", targetURL, foundZ)
		}
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(contentType, "image/") {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		io.Copy(w, resp.Body)
		if debugEnabled {
			log.Printf("Served tile: %s", targetURL)
		}
	} else {
		log.Printf("Unhandled status from Strava: %s for URL: %s", resp.Status, targetURL)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

func main() {
	debugEnv := os.Getenv("LOG_DEBUG")
	debugEnabled = debugEnv == "1" || strings.ToLower(debugEnv) == "true"

	scalingEnv := os.Getenv("ENABLE_SCALING")
	scalingEnabled = scalingEnv == "1" || strings.ToLower(scalingEnv) == "true"
	// Fetch cookies on startup
	getCookies()

	// Set up a ticker to refresh cookies periodically (every 6 hours)
	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		for range ticker.C {
			getCookies()
		}
	}()

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	handler := http.HandlerFunc(tileProxyHandler)

	// --- Configure and start HTTP Server ---
	httpServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: handler,
	}

	go func() {
		log.Printf("HTTP server starting on port %s", httpPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP ListenAndServe error: %v", err)
		}
	}()

	// --- Conditionally configure and start HTTPS Server ---
	var httpsServer *http.Server
	certFilePath := os.Getenv("CERT_PEM")
	keyFilePath := os.Getenv("KEY_PEM")

	if certFilePath != "" && keyFilePath != "" {
		httpsServer = &http.Server{
			Addr:    ":" + httpsPort,
			Handler: handler,
		}

		go func() {
			log.Printf("HTTPS server starting on port %s", httpsPort)
			log.Printf("Using certificate file: %s", certFilePath)
			log.Printf("Using key file: %s", keyFilePath)
			if err := httpsServer.ListenAndServeTLS(certFilePath, keyFilePath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS ListenAndServeTLS error: %v", err)
			}
		}()
	} else {
		log.Println("HTTPS not started. Set CERT_PEM and KEY_PEM environment variables to enable HTTPS.")
	}

	log.Println("http://localhost:" + httpPort + "/all/blue/{z}/{x}/{y}.png")
	log.Println("https://localhost:" + httpsPort + "/all/blue/{z}/{x}/{y}.png")

	// Wait for interrupt signal to gracefully shut down the servers
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	// Add HTTP server to wait group

	wg.Go(func() {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP Server Shutdown Failed: %v", err)
		}
	})

	if httpsServer != nil {
		// Add HTTPS server to wait group if it exists
		wg.Go(func() {
			if err := httpsServer.Shutdown(ctx); err != nil {
				log.Printf("HTTPS Server Shutdown Failed: %v", err)
			}
		})
	}

	wg.Wait()

	// Close idle connections in our persistent clients
	clientsLock.Lock()
	for host, client := range httpClients {
		if tr, ok := client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
			log.Printf("Closed idle connections for %s", host)
		}
	}
	clientsLock.Unlock()

	ticker.Stop()
	log.Println("Server stopped gracefully.")
}
