#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="nothing035/mcm:latest"
CONTAINER_NAME="mcm"
DEFAULT_DATA_DIR="$(pwd -P)"
DEFAULT_PORT="80"
PROMPT_INPUT="/dev/tty"

read_prompt() {
  local prompt="$1"
  local mode="${2:-}"
  local input

  if [[ "$mode" == "silent" ]]; then
    if ! IFS= read -r -s -u 3 -p "$prompt " input; then
      echo "Failed to read interactive input from $PROMPT_INPUT." >&2
      exit 1
    fi
    printf '\n' >&2
  elif ! IFS= read -r -u 3 -p "$prompt " input; then
    echo "Failed to read interactive input from $PROMPT_INPUT." >&2
    exit 1
  fi

  printf '%s\n' "$input"
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local input

  input="$(read_prompt "$prompt [$default_value]:")"
  if [[ -z "$input" ]]; then
    printf '%s\n' "$default_value"
    return
  fi

  printf '%s\n' "$input"
}

prompt_nonempty() {
  local prompt="$1"
  local input

  while true; do
    input="$(read_prompt "$prompt:")"
    if [[ -n "$input" ]]; then
      printf '%s\n' "$input"
      return
    fi
    echo "Value cannot be empty."
  done
}

prompt_password() {
  local password
  local confirmation

  while true; do
    password="$(read_prompt "Password:" "silent")"
    if [[ -z "$password" ]]; then
      echo "Password cannot be empty."
      continue
    fi

    confirmation="$(read_prompt "Confirm password:" "silent")"

    if [[ "$password" == "$confirmation" ]]; then
      printf '%s\n' "$password"
      return
    fi

    echo "Passwords do not match."
  done
}

validate_port() {
  local port="$1"

  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  if (( port < 1 || port > 65535 )); then
    return 1
  fi

  return 0
}

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
}

echo "MCM deployment"
echo

require_command docker

if [[ ! -r "$PROMPT_INPUT" ]]; then
  echo "Interactive terminal not available at $PROMPT_INPUT." >&2
  exit 1
fi

exec 3<"$PROMPT_INPUT"

if [[ ! -S /var/run/docker.sock ]]; then
  echo "Docker socket not found at /var/run/docker.sock." >&2
  echo "This script expects to deploy against the host Docker daemon." >&2
  exit 1
fi

while true; do
  WEBUI_PORT="$(prompt_with_default "Web UI port" "$DEFAULT_PORT")"
  if validate_port "$WEBUI_PORT"; then
    break
  fi
  echo "Port must be an integer between 1 and 65535."
done

AUTH_USERNAME="$(prompt_nonempty "Username")"
AUTH_PASSWORD="$(prompt_password)"
DATA_DIR="$(prompt_with_default "Data directory" "$DEFAULT_DATA_DIR")"
DATA_DIR="$(mkdir -p "$DATA_DIR" && cd "$DATA_DIR" && pwd -P)"

echo
echo "Pulling image $IMAGE_NAME..."
docker pull "$IMAGE_NAME"

echo "Generating password hash..."
PASSWORD_HASH="$(
  printf '%s\n' "$AUTH_PASSWORD" \
    | docker run --rm -i "$IMAGE_NAME" sh -lc 'IFS= read -r password; uv run hash-password "$password"' \
    | tr -d '\r' \
    | tail -n 1
)"
unset AUTH_PASSWORD

echo "Generating session secret..."
SESSION_SECRET="$(
  docker run --rm "$IMAGE_NAME" python -c 'import secrets; print(secrets.token_urlsafe(32))' \
    | tr -d '\r\n'
)"

if docker ps -a --format '{{.Names}}' | grep -Fx "$CONTAINER_NAME" >/dev/null 2>&1; then
  echo "Replacing existing container $CONTAINER_NAME..."
  docker rm -f "$CONTAINER_NAME" >/dev/null
fi

echo "Starting container $CONTAINER_NAME..."
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "$WEBUI_PORT:$WEBUI_PORT" \
  -e MCM_WEBUI_PORT="$WEBUI_PORT" \
  -e MCM_DATA_ROOT=/var/lib/mcm \
  -e MCM_AUTH_USERNAME="$AUTH_USERNAME" \
  -e MCM_AUTH_PASSWORD_HASH="$PASSWORD_HASH" \
  -e MCM_SESSION_SECRET="$SESSION_SECRET" \
  -e MCM_COOKIE_SECURE=false \
  -v "$DATA_DIR:/var/lib/mcm" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE_NAME" >/dev/null

HOST_ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "$HOST_ADDRESS" ]]; then
  HOST_ADDRESS="localhost"
fi

echo
echo "Deployment complete."
echo "Container: $CONTAINER_NAME"
echo "Image: $IMAGE_NAME"
echo "Web UI: http://$HOST_ADDRESS:$WEBUI_PORT"
echo "Data dir: $DATA_DIR"
