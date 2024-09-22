openssl genrsa -out ../client_private.key 2048

openssl req -new -key ../client_private.key -out ../client.csr -subj "/C=US/ST=State/L=City/O=ClientOrg/OU=ClientUnit/CN=client.example.com"

csr_content=$(cat ../client.csr | awk 'BEGIN {ORS = "\\n"} {print}')

echo "{\"csr\": \"$csr_content\"}"

curl -X POST \
     -H "Authorization: token123" \
     -H "Content-Type: application/json" \
     -d "{\"csr\": \"$csr_content\"}" \
     http://localhost:8080/issue -o ../client_cert.pem