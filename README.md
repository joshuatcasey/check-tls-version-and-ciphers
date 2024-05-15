# check-tls-version-and-ciphers

For use in testing Pinniped API.

Port-forward a kubernetes service: `kubectl port-forward service/pinniped-supervisor-nodeport 10447:443 -n supervisor`

Run this app: `go run main.go 127.0.0.1 10447`

Sample output (when the Pinniped supervisor is cipher-limited):

```shell
Using host "127.0.0.1" and port "10447"
Supported TLS Versions:
- TLS 1.2
- TLS 1.3
Supported TLS1.2 Ciphers:
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```