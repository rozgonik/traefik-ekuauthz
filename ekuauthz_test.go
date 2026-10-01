package traefik_ekuauthz_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"

	traefik_ekuauthz "github.com/rozgonik/traefik-ekuauthz"
)

const (
	clientAuthOID = "1.3.6.1.5.5.7.3.2"
	privateEKUOID = "1.3.6.1.4.1.55555.1.1"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	validConfig := func() *traefik_ekuauthz.Config {
		config := traefik_ekuauthz.CreateConfig()
		config.RequiredEKUs = []string{clientAuthOID}
		return config
	}

	testCases := []struct {
		name   string
		config *traefik_ekuauthz.Config
		next   http.Handler
	}{
		{name: "nil config", config: nil, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "nil next handler", config: validConfig(), next: nil},
		{name: "missing required EKUs", config: traefik_ekuauthz.CreateConfig(), next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "invalid OID", config: &traefik_ekuauthz.Config{StatusCode: 403, StatusText: "Forbidden", RequiredEKUs: []string{"not-an-oid"}}, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "invalid OID root", config: &traefik_ekuauthz.Config{StatusCode: 403, StatusText: "Forbidden", RequiredEKUs: []string{"1.40.1"}}, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "invalid status code", config: &traefik_ekuauthz.Config{StatusCode: 99, StatusText: "Forbidden", RequiredEKUs: []string{clientAuthOID}}, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		{name: "empty status text", config: &traefik_ekuauthz.Config{StatusCode: 403, RequiredEKUs: []string{clientAuthOID}}, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := traefik_ekuauthz.New(context.Background(), testCase.next, testCase.config, "eku-authz"); err == nil {
				t.Fatal("New() succeeded for an invalid configuration")
			}
		})
	}
}

func TestAllowsKnownEKU(t *testing.T) {
	handler := newHandler(t, []string{clientAuthOID})
	response := serve(handler, &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestAllowsUnknownEKU(t *testing.T) {
	handler := newHandler(t, []string{privateEKUOID})
	response := serve(handler, &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1, 1}}})

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestAllowsOnlyWhenAllRequiredEKUsArePresent(t *testing.T) {
	handler := newHandler(t, []string{clientAuthOID, privateEKUOID})
	certificate := &x509.Certificate{
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1, 1}},
	}

	response := serve(handler, certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestRejectsCertificateMissingRequiredEKU(t *testing.T) {
	handler := newHandler(t, []string{clientAuthOID, privateEKUOID})
	response := serve(handler, &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestRejectsRequestWithoutTLSOrClientCertificate(t *testing.T) {
	handler := newHandler(t, []string{clientAuthOID})

	t.Run("non TLS", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
	})

	t.Run("no peer certificate", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://example.test", nil)
		request.TLS = &tls.ConnectionState{}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
	})
}

func TestUsesConfiguredRejectionStatus(t *testing.T) {
	config := traefik_ekuauthz.CreateConfig()
	config.StatusCode = http.StatusUnauthorized
	config.StatusText = "EKU required"
	config.RequiredEKUs = []string{clientAuthOID}
	handler := newHandlerWithConfig(t, config)

	response := serve(handler, &x509.Certificate{})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response.Body.String() != "EKU required\n" {
		t.Fatalf("body = %q, want %q", response.Body.String(), "EKU required\n")
	}
}

func newHandler(t *testing.T, requiredEKUs []string) http.Handler {
	t.Helper()
	config := traefik_ekuauthz.CreateConfig()
	config.RequiredEKUs = requiredEKUs
	return newHandlerWithConfig(t, config)
}

func newHandlerWithConfig(t *testing.T, config *traefik_ekuauthz.Config) http.Handler {
	t.Helper()
	handler, err := traefik_ekuauthz.New(context.Background(), http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}), config, "eku-authz")
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(handler http.Handler, certificate *x509.Certificate) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://example.test", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
