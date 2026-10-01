package traefik_ekuauthz

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Config configures the extended-key-usage requirements for a client certificate.
// Every OID in RequiredEKUs must be present in the leaf certificate.
type Config struct {
	StatusCode   int      `yaml:"statusCode" json:"statusCode"`
	StatusText   string   `yaml:"statusText" json:"statusText"`
	RequiredEKUs []string `yaml:"requiredEKUs" json:"requiredEKUs"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{StatusCode: 403, StatusText: "Forbidden (mTLS)"}
}

type EkuAuthz struct {
	config       *Config
	next         http.Handler
	name         string
	requiredEKUs map[string]struct{}
}

var knownEKUOIDs = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "2.5.29.37.0",
	x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth:                     "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
	x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.10.3.6",
}

// New creates an EKU authorization middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration must not be nil")
	}
	if next == nil {
		return nil, fmt.Errorf("next handler must not be nil")
	}
	if config.StatusCode < 100 || config.StatusCode > 599 {
		return nil, fmt.Errorf("statusCode must be a valid HTTP status code")
	}
	if strings.TrimSpace(config.StatusText) == "" {
		return nil, fmt.Errorf("statusText must not be empty")
	}
	if len(config.RequiredEKUs) == 0 {
		return nil, fmt.Errorf("at least one requiredEKUs entry must be configured")
	}

	requiredEKUs := make(map[string]struct{}, len(config.RequiredEKUs))
	for _, configuredOID := range config.RequiredEKUs {
		oid, err := parseOID(configuredOID)
		if err != nil {
			return nil, fmt.Errorf("invalid required EKU %q: %w", configuredOID, err)
		}
		requiredEKUs[oid.String()] = struct{}{}
	}

	return &EkuAuthz{config: config, next: next, name: name, requiredEKUs: requiredEKUs}, nil
}

func (plugin *EkuAuthz) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.TLS == nil {
		plugin.reject(response, request, "non-TLS request")
		return
	}
	if len(request.TLS.PeerCertificates) == 0 {
		plugin.reject(response, request, "request without a client certificate")
		return
	}

	peerCert := request.TLS.PeerCertificates[0] // leaf certificate
	presentEKUs := certificateEKUs(peerCert)
	for requiredEKU := range plugin.requiredEKUs {
		if _, present := presentEKUs[requiredEKU]; !present {
			plugin.reject(response, request, fmt.Sprintf("certificate missing required EKU %s (CN: %q)", requiredEKU, peerCert.Subject.CommonName))
			return
		}
	}
	plugin.next.ServeHTTP(response, request)
}

func (plugin *EkuAuthz) reject(response http.ResponseWriter, request *http.Request, reason string) {
	log.Printf("%s: rejecting request from %s: %s", plugin.name, request.RemoteAddr, reason)
	http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
}

func certificateEKUs(cert *x509.Certificate) map[string]struct{} {
	ekus := make(map[string]struct{}, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, usage := range cert.ExtKeyUsage {
		if oid, ok := knownEKUOID(usage); ok {
			ekus[oid] = struct{}{}
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		ekus[oid.String()] = struct{}{}
	}
	return ekus
}

func knownEKUOID(usage x509.ExtKeyUsage) (string, bool) {
	oid, ok := knownEKUOIDs[usage]
	return oid, ok
}

func parseOID(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID must contain at least two components")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("invalid OID component %q", part)
		}
		component, err := strconv.Atoi(part)
		if err != nil || component < 0 {
			return nil, fmt.Errorf("invalid OID component %q", part)
		}
		oid[i] = component
	}
	if oid[0] > 2 || (oid[0] < 2 && oid[1] > 39) {
		return nil, fmt.Errorf("invalid OID root %s", value)
	}
	return oid, nil
}
