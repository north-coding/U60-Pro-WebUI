#!/bin/sh
# Project-owned proxy-only Agent launcher. This script never removes the
# abandoned Mihomo installation and never kills a process by numeric PID.
set -eu
umask 077
unset ZTE_AGENT_PASSWORD ZTE_AGENT_PIN

if [ "${U60_PROXY_TEST_MODE:-0}" = 1 ]; then
    ROOT=${U60_PROXY_TEST_ROOT:?test root required}
    CURL_BIN=${U60_PROXY_TEST_CURL_BIN:?test curl required}
    HOST_ARCH=${U60_PROXY_TEST_ARCH:-aarch64}
else
    ROOT=/data/u60-pro-managed
    CURL_BIN=/usr/bin/curl
    HOST_ARCH=$(uname -m)
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

AGENT_DIR=$ROOT/agent
MIHOMO_DIR=$ROOT/mihomo
AUTH_DIR=$ROOT/auth
AGENT=$AGENT_DIR/zte-agent
MIHOMO=$MIHOMO_DIR/mihomo
CONFIG=$MIHOMO_DIR/config.yaml
PASSWORD_FILE=$AUTH_DIR/password
WEBUI_ORIGIN_FILE=$AUTH_DIR/webui-origin
AGENT_LOG=$AGENT_DIR/agent.log
API=http://127.0.0.1:9090
HTTPS_ORIGIN=

fail() { echo "proxy-agent: $*" >&2; exit 1; }

metadata() {
    stat -c '%u %a %h' "$1" 2>/dev/null || stat -f '%u %Lp %l' "$1" 2>/dev/null || return 1
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

validate_dir() {
    local path
    path=$1
    if [ -L "$path" ] || [ ! -d "$path" ]; then
        fail "required managed directory is missing or linked: $path"
    fi
    set -- $(metadata "$path") || fail "cannot inspect directory: $path"
    [ "$1" = "$(id -u)" ] && [ "$2" = 700 ] || fail "directory must be owned by this service user with mode 0700: $path"
}

validate_file() {
    local path mode
    path=$1
    mode=$2
    if [ -L "$path" ] || [ ! -f "$path" ]; then
        fail "required managed file is missing or linked: $path"
    fi
    set -- $(metadata "$path") || fail "cannot inspect file: $path"
    [ "$1" = "$(id -u)" ] && [ "$2" = "$mode" ] && [ "$3" = 1 ] || fail "file must be owned, single-link, and mode $mode: $path"
}

validate_binary() {
    local path owner mode links expected actual info
    path=$1
    if [ -L "$path" ] || [ ! -f "$path" ] || [ ! -x "$path" ]; then
        fail "required executable is missing, linked, or not executable: $path"
    fi
    set -- $(metadata "$path") || fail "cannot inspect executable: $path"
    owner=$1 mode=$2 links=$3
    case "$mode" in 700|750|755|500|550|555) : ;; *) fail "executable has unexpected permissions: $path" ;; esac
    [ "$owner" = "$(id -u)" ] && [ "$links" = 1 ] || fail "executable must be owned and single-link: $path"
    validate_file "$path.sha256" 600
    validate_file "$path.arch" 600
    expected=$(cat "$path.sha256")
    actual=$(hash_file "$path") || fail "no SHA-256 utility is available"
    [ "$expected" = "$actual" ] || fail "executable digest mismatch: $path"
    [ "$(cat "$path.arch")" = aarch64 ] || fail "artifact is not marked as the required aarch64 build: $path"
    if [ "$path" = "$AGENT" ]; then
        info=$("$path" --build-info 2>/dev/null) || fail "Agent binary cannot execute its side-effect-free build check"
        case "$info" in *"arch=aarch64"*) : ;; *) fail "Agent binary does not report an aarch64 build" ;; esac
    fi
}

check_capability() {
    local response
    response=$("$CURL_BIN" --fail --silent --show-error --max-time 1 "$API/api/proxy/capabilities" 2>/dev/null) || return 1
    case "$response" in
        *'"mode":"proxy_only"'*'"proxy_management"'*) return 0 ;;
        *'"mode":"full"'*) return 2 ;;
        *) return 2 ;;
    esac
}

wait_for_capability() {
    local expected attempt result
    expected=$1
    attempt=0
    while [ "$attempt" -lt 15 ]; do
        if check_capability; then
            [ "$expected" = up ] && return 0
        else
            result=$?
            if [ "$result" -eq 2 ]; then
                fail "another Agent is serving this API; refusing to replace or signal it"
            fi
            [ "$expected" = down ] && return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    fail "timed out waiting for proxy-only Agent to become $expected"
}

preflight_agent() {
    if [ "${U60_PROXY_TEST_MODE:-0}" != 1 ] && [ "$(id -u)" != 0 ]; then
        fail "launcher must run as root on the U60"
    fi
    [ "$HOST_ARCH" = aarch64 ] || fail "device architecture is not aarch64"
    validate_dir "$ROOT"
    validate_dir "$AGENT_DIR"
    validate_dir "$MIHOMO_DIR"
    validate_dir "$AUTH_DIR"
    validate_file "$PASSWORD_FILE" 600
    IFS= read -r PASSWORD < "$PASSWORD_FILE" || fail "cannot read Agent credential file"
    case "$PASSWORD" in
        ''|*[!A-Za-z0-9_-]*) fail "password file must contain one nonempty base64url-safe password line" ;;
    esac
    if [ -L "$WEBUI_ORIGIN_FILE" ]; then
        fail "HTTPS WebUI origin must not be a symbolic link"
    elif [ -e "$WEBUI_ORIGIN_FILE" ]; then
        validate_file "$WEBUI_ORIGIN_FILE" 600
        awk 'NR > 1 { exit 1 } END { if (NR != 1) exit 1 }' "$WEBUI_ORIGIN_FILE" || fail "HTTPS WebUI origin must contain exactly one line"
        HTTPS_ORIGIN=$(cat "$WEBUI_ORIGIN_FILE")
        [ -n "$HTTPS_ORIGIN" ] || fail "HTTPS WebUI origin must not be empty"
        case "$HTTPS_ORIGIN" in https://*) : ;; *) fail "HTTPS WebUI origin must start with https://" ;; esac
    fi
    validate_binary "$AGENT"
    if [ -L "$AGENT_LOG" ]; then
        fail "Agent log must not be a symbolic link"
    elif [ -e "$AGENT_LOG" ]; then
        validate_file "$AGENT_LOG" 600
    else
        : > "$AGENT_LOG" || fail "cannot create Agent log"
        chmod 600 "$AGENT_LOG"
    fi
}

preflight_start() {
    preflight_agent
    validate_binary "$MIHOMO"
    info=$("$MIHOMO" -v 2>&1) || fail "managed Mihomo binary cannot execute"
    case "$info" in *arm64*) : ;; *) fail "Mihomo binary does not report the expected arm64 build" ;; esac
    if [ -e "$CONFIG" ] || [ -L "$CONFIG" ]; then
        validate_file "$CONFIG" 600
        "$MIHOMO" -t -d "$MIHOMO_DIR" -f "$CONFIG" >/dev/null 2>&1 || fail "managed Mihomo config validation failed; Agent was not started"
    fi
}

login_token() {
    local response token
    response=$(printf '{"password":"%s"}' "$PASSWORD" | "$CURL_BIN" --fail --silent --show-error --max-time 3 \
        -H 'Content-Type: application/json' --data-binary @- "$API/api/auth/login") || fail "Agent password authentication failed"
    token=$(printf '%s' "$response" | sed -n 's/.*"token":"\([0-9a-fA-F]*\)".*/\1/p')
    case "$token" in
        *[!0-9a-fA-F]*|'') fail "Agent returned an invalid session token" ;;
    esac
    [ "${#token}" -ge 32 ] || fail "Agent returned a short session token"
    printf '%s' "$token"
}

stop_agent() {
    local preserve token config_file preserve_json response result
    preserve=$1
    if check_capability; then
        :
    else
        result=$?
        [ "$result" -eq 1 ] && return 0
        fail "refusing to stop an Agent with an unexpected capability response"
    fi
    token=$(login_token)
    config_file=$(mktemp "$AGENT_DIR/.curl-auth.XXXXXX") || fail "cannot create private request config"
    chmod 600 "$config_file"
    trap 'rm -f "$config_file"' EXIT HUP INT TERM
    printf 'header = "Authorization: Bearer %s"\n' "$token" > "$config_file"
    preserve_json=false
    [ "$preserve" = true ] && preserve_json=true
    response=$("$CURL_BIN" --fail --silent --show-error --max-time 5 --config "$config_file" \
        -H 'Content-Type: application/json' -H 'X-Confirm: true' \
        --data-binary "{\"preserve_mihomo\":$preserve_json}" "$API/api/proxy/agent/stop") || fail "authenticated Agent shutdown request failed"
    case "$response" in *'"stopping":true'*) : ;; *) fail "Agent did not confirm shutdown" ;; esac
    rm -f "$config_file"
    trap - EXIT HUP INT TERM
}

start_agent() {
    local result
    preflight_start
    if check_capability; then
        echo "proxy-only Agent is already running"
        return 0
    else
        result=$?
        [ "$result" -eq 1 ] || fail "an incompatible service already owns API port 9090"
    fi
    if [ -n "$HTTPS_ORIGIN" ]; then
        (umask 077; ZTE_AGENT_PASSWORD_FILE="$PASSWORD_FILE" nohup "$AGENT" --proxy-only --proxy-bind 127.0.0.1:9090 \
            --proxy-https-origin "$HTTPS_ORIGIN" </dev/null >> "$AGENT_LOG" 2>&1 &)
    else
        (umask 077; ZTE_AGENT_PASSWORD_FILE="$PASSWORD_FILE" nohup "$AGENT" --proxy-only --proxy-bind 127.0.0.1:9090 \
            </dev/null >> "$AGENT_LOG" 2>&1 &)
    fi
    wait_for_capability up
    echo "proxy-only Agent is ready on 127.0.0.1:9090"
}

case "${1:-}" in
    start)
        start_agent
        ;;
    stop)
        preflight_agent
        stop_agent false
        wait_for_capability down
        echo "proxy-only Agent stopped; managed Mihomo is stopped and cached state is retained"
        ;;
    restart)
        preflight_start
        stop_agent true
        wait_for_capability down
        start_agent
        echo "proxy-only Agent restarted; verified Mihomo remains available for recovery"
        ;;
    status)
        if check_capability; then
            echo "proxy-only Agent is running"
        else
            result=$?
            [ "$result" -eq 1 ] && { echo "proxy-only Agent is stopped"; exit 1; }
            fail "an incompatible service is responding on API port 9090"
        fi
        ;;
    *)
        fail "usage: $0 {start|stop|restart|status}"
        ;;
esac
