# Client Certificate EKU Authorization Plugin for traefik

This plugin authorizes requests based on the EKU field of a TLS client certificate.
If the client does not present a certificate or does present a certificate which according to
configuration is not allowed to continue, `403 Forbidden` is returned.

**CAUTION:**
This plugin does not validate the certificate it receives.
Please use the [traefik mTLS configuration](https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls)
to also validate the certificate against a CA that you specify.

## Configuration

### Static configuration
```yaml
experimental:
  plugins:
    ekuauthz:
      moduleName: "github.com/rozgonik/traefik-ekuauthz"
      version: "v0.1.0"
```

### Dynamic configuration
```yaml
http:
  middlewares:
    my-ekuauthz:
      plugin:
        ekuauthz:
          requiredEKUs:
            - "1.3.6.1.4.1.1.1.1"

  routers:
    my-router:
      middlewares:
        - "my-ekuauthz"
      tls:
        # Traefik mtls configuration is required for certificate validation
        # https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls
        options: my-mtls
      entrypoints: […]
      rule: …
      service: …

tls:
  options:
    my-mtls:
      clientAuth:
        caFiles:
          - /etc/ssl/certs/ca-certificates.crt
        clientAuthType: RequireAndVerifyClientCert
```

`requiredEKUs` is a non-empty list of dotted-decimal EKU OIDs. All listed
OIDs must be present in the leaf client certificate. Standard EKUs parsed by
Go (for example client authentication, `1.3.6.1.5.5.7.3.2`) and private or
otherwise unknown EKUs are both supported.
