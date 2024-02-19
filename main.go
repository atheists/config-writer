package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/atheists/config-writer/internal/firewall"
)

const (
	port    = "3000"
	rootDir = "/output"
)

func main() {
	logger := slog.Default()
	logger.Info("Starting server...")

	fw, err := firewall.New(os.Getenv("ALLOWED_CIDRS"), logger)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/api/v1/config-files", handler(fw, logger))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":"+port), nil))
}

type payload struct {
	Files []struct {
		Path     string `json:"path"`
		Contents string `json:"contents"`
	} `json:"files"`
}

func respondWithError(w http.ResponseWriter, code int, logger *slog.Logger, msg string, err error) {
	logger.Info(msg, "response-code", code, "error", err)
	http.Error(w, msg, code)
}

func handler(fw *firewall.Firewall, logger *slog.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logger.With("remote-addr", r.RemoteAddr, "request-path", r.URL.Path, "http-method", r.Method)
		logger.Info("Got request")
		if !fw.Authorized(r.RemoteAddr) {
			respondWithError(w, http.StatusForbidden, logger, "Access denied", nil)
			return
		}

		if r.Method != http.MethodPost {
			respondWithError(w, http.StatusMethodNotAllowed, logger, "Method not allowed", nil)
			return
		}

		var payload payload
		bs, err := io.ReadAll(r.Body)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, logger, "Failed to read request body", err)
			return
		}
		if err = json.Unmarshal(bs, &payload); err != nil {
			respondWithError(w, http.StatusBadRequest, logger, "Failed to parse request body", err)
			return
		}

		for _, file := range payload.Files {
			if !filepath.IsLocal(file.Path) {
				respondWithError(w, http.StatusBadRequest, logger, fmt.Sprintf("Refusing to write file outside root: %q", file.Path), nil)
				return
			}
		}

		for _, file := range payload.Files {
			fullPath := filepath.Join(rootDir, file.Path)
			if err := os.MkdirAll(path.Dir(fullPath), 0700); err != nil {
				respondWithError(w, http.StatusInternalServerError, logger, fmt.Sprintf("Error creating directory for path: %q", fullPath), err)
				return
			}
			if err := os.WriteFile(fullPath, []byte(file.Contents), 0700); err != nil {
				respondWithError(w, http.StatusInternalServerError, logger, fmt.Sprintf("Error writing file at path: %q", fullPath), err)
				return
			}
			logger.Info("Wrote file", "file-path", fullPath)
		}
		logger.Info("Success")
	}
}
