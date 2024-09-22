# Certificate Authority API

This is a simple PoC Certificate Authority API that allows you to request a certificate using a Certificate Signing Request (CSR).

## Generate client certificate with script
### Generate client private key and CSR and make api call
```bash
./scripts/cert_request.sh
```

## Generate client certificate manually
### Generate client private key and CSR
```
openssl genrsa -out client_private.key 2048

openssl req -new -key client_private.key -out client.csr -subj "/C=US/ST=State/L=City/O=ClientOrg/OU=ClientUnit/CN=client.example.com"
```

### Prepare CSR for api request
```bash
csr_content=$(cat client.csr | awk 'BEGIN {ORS = "\\n"} {print}')

# Alternative
#csr_content=$(cat client.csr | sed ':a;N;$!ba;s/\n/\\n/g')

# Alternative
#csr_base64=$(base64 -w 0 client.csr)

curl -X POST \
     -H "Authorization: token123" \
     -H "Content-Type: application/json" \
     -d "{\"csr\": \"$csr_base64\"}" \
     http://localhost:8080/issue -o client_cert.pem
````