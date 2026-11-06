#!/usr/bin/env bash
# Levanta dos servidores TLS locales para probar el inventario sin depender de internet:
#   - localhost:8443  certificado RSA-2048        (simula portal legado del banco)
#   - localhost:8444  certificado ECDSA P-256     (simula API moderna)
# Ambos son clasicos -> el inventario debe marcarlos como VULNERABLE (Shor).
#
# Uso:   bash lab/local-tls/start_servers.sh
# Parar: bash lab/local-tls/start_servers.sh stop
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$DIR/certs"   # ignorado por .gitignore: aqui viven llaves privadas

if [[ "${1:-}" == "stop" ]]; then
    pkill -f "openssl s_server -accept 844[34]" && echo "Servidores detenidos" || echo "No habia servidores"
    exit 0
fi

mkdir -p "$CERTS"
chmod 700 "$CERTS"

# RSA-2048 autofirmado, valido 30 dias
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$CERTS/rsa.key" -out "$CERTS/rsa.crt" \
    -subj "/CN=legacy-portal.bank.lab/O=PQC Lab Bank" 2>/dev/null

# ECDSA P-256 autofirmado, valido 30 dias
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -keyout "$CERTS/ec.key" -out "$CERTS/ec.crt" \
    -subj "/CN=payments-api.bank.lab/O=PQC Lab Bank" 2>/dev/null

chmod 600 "$CERTS"/*.key

openssl s_server -accept 8443 -cert "$CERTS/rsa.crt" -key "$CERTS/rsa.key" -www -quiet &
openssl s_server -accept 8444 -cert "$CERTS/ec.crt"  -key "$CERTS/ec.key"  -www -quiet &
sleep 1
echo "Listo: localhost:8443 (RSA-2048) y localhost:8444 (ECDSA P-256)"
echo "Detener con: bash $0 stop"
