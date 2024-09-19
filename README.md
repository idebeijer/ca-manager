
## inspect cert
```bash
openssl x509 -noout -text -in issued.pem
```

## extract client cert from issued cert 
```bash
openssl x509 -in client_cert_and_key.pem -out client_cert.pem
```

## verify validity and check if generate by CA
```bash
openssl verify -CAfile ca_cert.pem client_cert.pem
```