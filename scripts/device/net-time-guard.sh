#!/bin/sh
# net_time_guard.sh — keep two firmware-reverted settings in place.
#
# 1. LAN IPv6 off. The carrier gives one /64 and no prefix delegation, so
#    LAN clients could have global IPv6 only through odhcpd relaying the
#    carrier's RA, and that took an on-link /64 route, RS kicks after every
#    prefix change and an IPA notrack in the agent, and still left clients on
#    dead prefixes after WAN reconnects (2026-10-28 to 11-15). Since
#    2026-11-16 the LAN is IPv4 only, at the user's request: odhcpd sends no
#    RA, serves no DHCPv6 and relays no NDP on lan. zte_router writes
#    dhcp.lan back to ra/dhcpv6=server at boot and after WAN events (eight
#    times in four hours on 2026-11-15), so it is checked every CHECK_SECS.
#    Its server-mode RAs in between carry no prefix (br-lan has no global
#    address), so clients get no global IPv6 from them; switching relay to
#    server also made a Mac drop its IPv6 default route and deprecate the
#    relayed prefix at once (2026-11-16). dhcp.wan_v6 (relay master, NDP
#    relay off) is left as it is: with no LAN slave it relays nothing. The
#    router's own WAN IPv6 does not depend on odhcpd.
# 2. Clock: ZTE's NITZ time sync writes Beijing wall time into the kernel
#    clock while the OS timezone is UTC, so the epoch runs 8h fast (again
#    after every WAN reconnect). The OS timezone is CST-8 now; this keeps the
#    kernel clock on true UTC using the Date header of a domestic HTTP server
#    (no ntpd on this firmware).
#
# Runs from rc.local; survives via nohup. Logs to /tmp/net_time_guard.log
# (rotated at 32KB).

LOG=/tmp/net_time_guard.log
BOOT_DELAY=90             # let zte_router finish its boot-time rewrites
CHECK_SECS=15             # dhcp.lan check (three uci reads)
CLOCK_SECS=300
MAX_SKEW=60
MAX_LOG=32768
TIME_URLS="http://www.baidu.com http://www.qq.com http://www.aliyun.com"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; [ -s "$LOG" ] && [ "$(wc -c < "$LOG")" -gt $MAX_LOG ] && tail -c $((MAX_LOG / 2)) "$LOG" > "$LOG.new" 2>/dev/null && mv "$LOG.new" "$LOG"; }

lan_v6_off() {
    # Do not commit another caller's staged DHCP changes.
    [ -z "$(uci -q changes dhcp)" ] || return 0
    changed=0
    for o in ra dhcpv6 ndp; do
        [ "$(uci -q get dhcp.lan.$o)" = disabled ] || { uci set dhcp.lan.$o=disabled; changed=1; }
    done
    [ $changed = 1 ] || return 0
    uci commit dhcp
    /etc/init.d/odhcpd restart >/dev/null 2>&1
    log "LAN IPv6 turned off again (dhcp.lan ra/dhcpv6/ndp disabled)"
}

fix_clock() {
    for url in $TIME_URLS; do
        hdr=$(curl -sI -m 5 "$url" 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: //p' | head -1)
        [ -n "$hdr" ] || continue
        real=$(date -u -D "%a, %d %b %Y %H:%M:%S GMT" -d "$hdr" +%s 2>/dev/null) || continue
        now=$(date +%s)
        skew=$((now - real))
        [ ${skew#-} -le $MAX_SKEW ] && return 0
        date -u -s "$(date -u -D "%a, %d %b %Y %H:%M:%S GMT" -d "$hdr" '+%Y-%m-%d %H:%M:%S')" >/dev/null 2>&1 \
            && log "clock skew ${skew}s corrected from $url"
        return 0
    done
    log "clock check failed: no HTTP Date header"
}

# musl here reads /etc/localtime (-> /tmp/localtime) and ignores /etc/TZ, and
# the firmware ships no zoneinfo; link our copied TZif before daemons start.
[ -f /data/zoneinfo/Asia/Shanghai ] && ln -sf /data/zoneinfo/Asia/Shanghai /tmp/localtime

sleep $BOOT_DELAY
n=0
while :; do
    lan_v6_off
    [ $((n % (CLOCK_SECS / CHECK_SECS))) = 0 ] && fix_clock
    n=$((n + 1))
    sleep $CHECK_SECS
done
