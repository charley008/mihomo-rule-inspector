package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"mihomo-rule-inspector/internal/config"
	webui "mihomo-rule-inspector/web"
)

type Server struct {
	mu       sync.RWMutex
	config   config.AppConfig
	logs     *LogCollector
	upgrader websocket.Upgrader
	mux      *http.ServeMux
}

func New(cfg config.AppConfig) *Server {
	s := &Server{
		config: cfg,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		mux: http.NewServeMux(),
	}
	s.logs = NewLogCollector(func() config.AppConfig {
		return s.currentConfig()
	})
	s.routes()
	return s
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.currentConfig().ListenAddr, s.withJSONLogging(s.mux))
}

func (s *Server) Handler() http.Handler {
	return s.withJSONLogging(s.mux)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.logs != nil {
		s.logs.Stop()
	}
	return nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/config", s.handleConfig)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/probe", s.handleProbe)
	s.mux.HandleFunc("/api/batch-probe", s.handleBatchProbe)
	s.mux.HandleFunc("/api/rules", s.handleRules)
	s.mux.HandleFunc("/api/connections", s.handleConnections)
	s.mux.HandleFunc("/api/logs", s.handleLogs)
	s.mux.HandleFunc("/api/logs/ws", s.handleLogsWS)
	s.mux.HandleFunc("/api/connections/ws", s.handleConnectionsWS)

	sub, err := fs.Sub(webui.Files, ".")
	if err == nil {
		s.mux.Handle("/", http.FileServerFS(sub))
	}
}

func (s *Server) currentConfig() config.AppConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *Server) updateConfig(cfg config.AppConfig) error {
	if err := config.Save(cfg); err != nil {
		return err
	}
	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()
	if s.logs != nil {
		s.logs.Restart()
	}
	return nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func (s *Server) withJSONLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
