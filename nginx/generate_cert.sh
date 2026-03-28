#!/bin/bash
# Run this once to generate self-signed SSL certificate for nginx
# Place output files in nginx/certs/

mkdir -p nginx/certs

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout nginx/certs/key.pem \
  -out    nginx/certs/cert.pem \
  -subj   "/C=IN/ST=State/L=City/O=DDoS-Defense/CN=localhost"

echo "✅ SSL certificate generated in nginx/certs/"
echo "   cert.pem  — certificate"
echo "   key.pem   — private key"
