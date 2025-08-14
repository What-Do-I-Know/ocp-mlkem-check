package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Result struct {
	ServerURL      string `json:"serverURL"`
	TLSVersion     string `json:"tlsVersion"`
	CipherSuite    string `json:"cipherSuite"`
	CurveID        string `json:"curveID"`
	DidResume      bool   `json:"didResume"`
	HandshakeMS    int64  `json:"handshakeMillis"`
	HTTPStatus     int    `json:"httpStatus"`
	UsedMLKEM      bool   `json:"usedMLKEM"`
	Error          string `json:"error,omitempty"`
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cipherSuiteToString(cs uint16) string {
	// TLS 1.3 cipher suites are fixed set; others we print numeric if unknown.
	switch cs {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("0x%04x", cs)
	}
}

func curveIDToString(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case 0:
		return "none"
	default:
		return fmt.Sprintf("CurveID(%d)", id)
	}
}

func loadInClusterCA() (*x509.CertPool, error) {
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(data) {
		return nil, errors.New("failed to append in-cluster CA certs")
	}
	return p, nil
}

func main() {
	var (
		server        = flag.String("server", "", "API server URL (default: in-cluster https://kubernetes.default.svc:443)")
		caFile        = flag.String("ca-file", "", "Custom CA bundle (PEM). Defaults to in-cluster CA if running in cluster; else system roots.")
		insecure      = flag.Bool("insecure-skip-verify", false, "Skip TLS verification (NOT recommended)")
		forceMLKEM    = flag.Bool("force-mlkem", false, "Prefer X25519MLKEM768 for key exchange")
		classicalOnly = flag.Bool("classical-only", false, "Do not offer PQ groups (use classical only)")
		requireMLKEM  = flag.Bool("require-mlkem", false, "Exit non-zero unless the negotiated CurveID is X25519MLKEM768")
		timeout       = flag.Duration("timeout", 5*time.Second, "Overall HTTP client timeout")
		path          = flag.String("path", "/version", "HTTP path to GET (only for completing TLS handshake; can be unauthorized)")
	)
	flag.Parse()

	target := *server
	if target == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			fmt.Fprintln(os.Stderr, "No --server and not running in cluster; please set --server, e.g. https://api.example:6443")
			os.Exit(2)
		}
		target = "https://" + net.JoinHostPort(host, port)
	}

	// Build tls.Config
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS13, // ensure TLS 1.3 so hybrid KEMs are on the table
	}

	// Roots: in-cluster CA if available by default; else system roots.
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read ca-file:", err)
			os.Exit(2)
		}
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "invalid ca-file: no certs")
			os.Exit(2)
		}
		tcfg.RootCAs = p
	} else {
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			if p, err := loadInClusterCA(); err == nil {
				tcfg.RootCAs = p
			}
		}
	}

	tcfg.InsecureSkipVerify = *insecure

	// Key exchange preferences
	if *forceMLKEM && *classicalOnly {
		fmt.Fprintln(os.Stderr, "--force-mlkem and --classical-only are mutually exclusive")
		os.Exit(2)
	}
	switch {
	case *forceMLKEM:
		tcfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	case *classicalOnly:
		tcfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	default:
		// Leave empty to use Go defaults (which include ML-KEM from Go 1.24+).
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tcfg,
		ForceAttemptHTTP2:   false, // keep it simple; TLS is what we care about
		MaxIdleConns:        1,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	url := strings.TrimRight(target, "/") + *path

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)

	result := Result{
		ServerURL:   url,
		HandshakeMS: elapsed.Milliseconds(),
	}

	// Pull TLS state from the connection pool via Response
	if resp != nil && resp.TLS != nil {
		st := resp.TLS
		result.TLSVersion = tlsVersionToString(st.Version)
		result.CipherSuite = cipherSuiteToString(st.CipherSuite)
		result.CurveID = curveIDToString(st.CurveID)
		result.DidResume = st.DidResume
		result.HTTPStatus = resp.StatusCode
		result.UsedMLKEM = (st.CurveID == tls.X25519MLKEM768)
	} else if err == nil {
		result.Error = "no TLS state available"
	}
	if err != nil {
		result.Error = err.Error()
	}

	// Drain/close body
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Enforce requirement if requested
	exit := 0
	if *requireMLKEM && !result.UsedMLKEM {
		exit = 3
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	os.Exit(exit)
}
