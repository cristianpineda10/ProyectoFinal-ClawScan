#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
export PROJECT_DIR="$ROOT_DIR"
export DOCKER_GID="${DOCKER_GID:-$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo 0)}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker no está instalado o no está disponible en PATH." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Se requiere Docker Compose v2 (docker compose)." >&2
  exit 1
fi

mkdir -p reports targets
docker compose build clawscan claw-backend claw-frontend
docker compose up -d
echo "Sandbox listo: http://localhost:4321"
echo "API: http://localhost:3001/api/health"
