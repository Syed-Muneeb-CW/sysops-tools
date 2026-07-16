#!/usr/bin/env bash
###############################################################################
#  cpu-investigator.sh   (v3)
#
#  READ-ONLY server CPU / load spike investigation tool
#  (Cloudways-style stacks: nginx + php-fpm + per-app log dirs)
#
#  Strictly read-only: no file writes, no service restarts, no config changes.
#  Only cat/zcat/grep/awk/atopsar over logs.
#
#  Usage:
#      ./cpu-investigator.sh              (interactive)
#      ./cpu-investigator.sh 2026-07-13   (specific past date)
###############################################################################

set -o pipefail
export LC_ALL=C          # predictable text handling, faster grep

# ------------------------------- appearance ---------------------------------
if [ -t 1 ]; then
    RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CYN=$'\e[36m'
    BLD=$'\e[1m';  RST=$'\e[0m'
else
    RED=""; GRN=""; YLW=""; CYN=""; BLD=""; RST=""
fi
hr()      { printf '%s\n' "------------------------------------------------------------------------"; }
section() { echo; hr; echo "${BLD}${CYN}== $1${RST}"; hr; }
note()    { echo "${YLW}[i]${RST} $1"; }
ok()      { echo "${GRN}[+]${RST} $1"; }
warn()    { echo "${RED}[!]${RST} $1"; }

APPS_BASE="/home/master/applications"

###############################################################################
# 0. Target date selection
###############################################################################
TODAY=$(date +%F)
TARGET_DATE="$1"
if [ -z "$TARGET_DATE" ]; then
    echo "${BLD}Server CPU Spike Investigator (read-only)${RST}"
    echo
    read -rp "Analyze last 24 hours (today)? [Y/n, or enter a past date YYYY-MM-DD]: " ANSW
    case "$ANSW" in
        ""|y|Y|yes|YES|24|24h|24H) TARGET_DATE="$TODAY" ;;
        n|N|no|NO) read -rp "Enter date to analyze (YYYY-MM-DD): " TARGET_DATE ;;
        *) TARGET_DATE="$ANSW" ;;
    esac
fi
if ! date -d "$TARGET_DATE" >/dev/null 2>&1; then
    warn "Invalid date: '$TARGET_DATE'. Use YYYY-MM-DD."; exit 1
fi
TARGET_DATE=$(date -d "$TARGET_DATE" +%F)

D_DASH=$(date -d "$TARGET_DATE" '+%d-%b-%Y')     # 16-Jul-2026 (php-fpm/slow log)
D_SLASH=$(date -d "$TARGET_DATE" '+%d/%b/%Y')    # 16/Jul/2026 (access logs)
D_NGX=$(date -d "$TARGET_DATE" '+%Y/%m/%d')      # 2026/07/16  (nginx error logs)
D_SYSLOG=$(date -d "$TARGET_DATE" '+%b %e')      # Jul 16      (classic syslog)
D_ISO="$TARGET_DATE"                             # 2026-07-16
D_ATOP=$(date -d "$TARGET_DATE" '+%Y%m%d')       # 20260716

IS_HISTORIC=0
[ "$TARGET_DATE" != "$TODAY" ] && IS_HISTORIC=1

# Read a log family incl. rotated copies. Always binary-safe via grep -a later.
read_logs() {
    local base="$1" f
    {
        for f in "$base" "$base".1; do [ -r "$f" ] && cat -- "$f" 2>/dev/null; done
        for f in "$base".*.gz; do [ -r "$f" ] && zcat -- "$f" 2>/dev/null; done
    } | tr -d '\000'
    return 0
}

# Geo/owner lookup for an IP (IPv4 + IPv6) — offline DB first, whois as
# read-only network fallback (top IPs only, 5s timeout). Output sanitized.
geo_ip() {
    local ip="$1" out=""
    # 1) Offline GeoIP legacy DB (v4 and v6 use different binaries)
    if [[ "$ip" == *:* ]]; then
        command -v geoiplookup6 >/dev/null 2>&1 && \
            out=$(geoiplookup6 "$ip" 2>/dev/null | head -1 | sed 's/^[^:]*: //')
    else
        command -v geoiplookup >/dev/null 2>&1 && \
            out=$(geoiplookup "$ip" 2>/dev/null | head -1 | sed 's/^[^:]*: //')
    fi
    echo "$out" | grep -qaiE "can.t resolve|not found|unknown|error" && out=""
    # 2) Offline MaxMind mmdb (handles both v4/v6)
    if [ -z "$out" ] && command -v mmdblookup >/dev/null 2>&1; then
        local db
        db=$(ls /var/lib/GeoIP/*Country*.mmdb /usr/share/GeoIP/*Country*.mmdb 2>/dev/null | head -1)
        [ -n "$db" ] && out=$(mmdblookup --file "$db" --ip "$ip" country names en 2>/dev/null \
                              | grep -oaP '"\K[^"]+' | head -1)
    fi
    # 3) whois (read-only network query)
    if [ -z "$out" ] && command -v whois >/dev/null 2>&1; then
        out=$(timeout 5 whois "$ip" 2>/dev/null \
              | grep -aiE '^(country|org-?name|netname|descr):' \
              | awk -F': *' '!seen[tolower($1)]++ {printf "%s / ", $2}' \
              | sed 's| / $||')
    fi
    out=$(echo "$out" | tr -d '\r' | tr -s ' ' | cut -c1-55)
    echo "${out:-n/a (install geoip-bin + geoip-database for offline lookups)}"
}

###############################################################################
# 1. Server time
###############################################################################
section "1. SERVER TIME"
date
note "Target date under investigation: ${BLD}${TARGET_DATE}${RST}$( [ $IS_HISTORIC -eq 1 ] && echo ' (historic — rotated logs included)' )"

###############################################################################
# 2. PHP version
###############################################################################
section "2. PHP VERSION"
if ! command -v php >/dev/null 2>&1; then
    warn "php binary not found in PATH."
    read -rp "Enter PHP version manually (e.g. 8.3): " PHP_VER
else
    php -v | head -n 1
    PHP_VER=$(php -v 2>/dev/null | head -n1 | grep -oaP 'PHP \K[0-9]+\.[0-9]+')
fi
FPM_LOG="/var/log/php${PHP_VER}-fpm.log"
if [ ! -r "$FPM_LOG" ]; then
    ALT=$(ls /var/log/php*-fpm.log 2>/dev/null | head -n1)
    if [ -n "$ALT" ]; then
        FPM_LOG="$ALT"
        PHP_VER=$(basename "$FPM_LOG" | grep -oaP 'php\K[0-9.]+(?=-fpm)')
        note "Falling back to detected FPM log: $FPM_LOG"
    else
        warn "No php-fpm log found under /var/log."
    fi
fi
ok "PHP version: ${PHP_VER:-unknown}   FPM log: $FPM_LOG"

###############################################################################
# 3. pm.max_children breaches
###############################################################################
section "3. PHP-FPM pm.max_children BREACHES ($TARGET_DATE)"
FPM_HITS=""
[ -n "$FPM_LOG" ] && FPM_HITS=$(read_logs "$FPM_LOG" | grep -a "pm.max_children" | grep -a "^\[$D_DASH")

if [ -n "$FPM_HITS" ]; then
    echo "$FPM_HITS"
    warn "Total breaches on $TARGET_DATE: $(echo "$FPM_HITS" | wc -l)"
else
    ok "No pm.max_children breaches found for $TARGET_DATE."
fi

POOLS=$(echo "$FPM_HITS" | grep -oaP '\[pool \K[^\]]+' | sort -u)
HOURS=$(echo "$FPM_HITS" | grep -oaP '^\[\d{2}-\w{3}-\d{4} \K\d{2}' | sort -u)
BREACH_MINUTES=$(echo "$FPM_HITS" | grep -oaP '^\[\d{2}-\w{3}-\d{4} \K\d{2}:\d{2}' | sort -u)

[ -n "$POOLS" ] && note "Affected pool(s): $(echo $POOLS | tr '\n' ' ')"
[ -n "$BREACH_MINUTES" ] && note "Exact breach minute(s): $(echo $BREACH_MINUTES | tr '\n' ' ')"

###############################################################################
# 4. oom-killer events
###############################################################################
section "4. OOM-KILLER EVENTS ($TARGET_DATE)"
OOM_HITS=$( { read_logs /var/log/syslog; read_logs /var/log/kern.log; } 2>/dev/null \
            | grep -ai "oom-killer" | grep -aE "^($D_SYSLOG|$D_ISO)" )
if [ -n "$OOM_HITS" ]; then
    echo "$OOM_HITS"
    warn "oom-killer WAS triggered on $TARGET_DATE — memory exhaustion confirmed."
    OOM_HOURS=$(echo "$OOM_HITS" | grep -oaP '(\d{2}):\d{2}:\d{2}' | cut -d: -f1 | sort -u)
    HOURS=$(printf '%s\n%s\n' "$HOURS" "$OOM_HOURS" | sort -u | sed '/^$/d')
else
    ok "No oom-killer events found in syslog/kern.log for $TARGET_DATE."
fi

if [ -z "$FPM_HITS" ] && [ -z "$OOM_HITS" ]; then
    note "Nothing breached on $TARGET_DATE."
    read -rp "Enter an hour to inspect anyway (00-23, or Enter to exit): " MANUAL_HOUR
    [ -z "$MANUAL_HOUR" ] && { echo; ok "Server looks clean for $TARGET_DATE. Done."; exit 0; }
    HOURS="$MANUAL_HOUR"
    POOLS=$(ls "$APPS_BASE" 2>/dev/null)
fi

###############################################################################
# 5. Per-application deep dive
###############################################################################
declare -A SUM_SLOW SUM_REQ SUM_ERR SUM_CRON
declare -A TOP_MOD TOP_IP TOP_IP_CNT TOP_IP_UA TOP_URI TOP_URI_CNT PHP_TOTSEC HEAVY_MIN SLOWEST_URI SLOWEST_SEC SUSP_IPS

for POOL in $POOLS; do
    APP_LOGS="$APPS_BASE/$POOL/logs"
    section "5. APPLICATION ANALYSIS — pool '$POOL'  ($APP_LOGS)"
    if [ ! -d "$APP_LOGS" ]; then warn "Directory not found: $APP_LOGS — skipping."; continue; fi

    for HH in $HOURS; do
        echo
        echo "${BLD}${YLW}>>> Time window ${TARGET_DATE} ${HH}:00 - ${HH}:59 <<<${RST}"

        # ---- 5a. PHP slow log ------------------------------------------------
        SLOW_LOG="$APP_LOGS/php-app.slow.log"
        SLOW_IN_WIN=$(read_logs "$SLOW_LOG" | grep -ac "^\[$D_DASH ${HH}:")
        echo
        echo "  ${BLD}[php-app.slow.log]${RST} slow-script events in window: $SLOW_IN_WIN"
        if [ "$SLOW_IN_WIN" -gt 0 ]; then
            # Count each module/plugin ONCE PER slow entry (not per stack frame),
            # using paragraph mode + index() to avoid regex-escaping pitfalls.
            echo "  Modules/plugins involved (counted once per slow entry, this window):"
            MOD_STATS=$(read_logs "$SLOW_LOG" | awk -v RS="" -v pfx="[$D_DASH ${HH}:" '
                index($0, pfx) == 1 || index($0, "\n" pfx) > 0 {
                    split("", seen); s = $0
                    while (match(s, /\/(modules|wp-content\/plugins)\/[A-Za-z0-9._-]+/)) {
                        m = substr(s, RSTART, RLENGTH)
                        sub(/^\/(modules|wp-content\/plugins)\//, "", m)
                        if (!(m in seen)) { seen[m] = 1; print m }
                        s = substr(s, RSTART + RLENGTH)
                    }
                }' | sort | uniq -c | sort -rn)
            echo "$MOD_STATS" | head -5 | sed 's/^/      /'
            [ -z "${TOP_MOD[$POOL]}" ] && TOP_MOD[$POOL]=$(echo "$MOD_STATS" | head -1 | awk '{print $2" ("$1" slow entries)"}')
            SUM_SLOW[$POOL]=$(( ${SUM_SLOW[$POOL]:-0} + SLOW_IN_WIN ))
        fi

        # ---- 5b. Web access logs (combined format) ---------------------------
        echo
        echo "  ${BLD}[web access logs — backend_*/static_*]${RST}"
        ACC_TMP=$(for f in "$APP_LOGS"/backend_*access.log "$APP_LOGS"/static_*access.log; do
                      [ -r "$f" ] && read_logs "$f"
                  done | grep -a "\[$D_SLASH:${HH}:")
        REQ_IN_WIN=$(printf '%s' "$ACC_TMP" | grep -ac .)
        echo "  Requests in window: $REQ_IN_WIN"
        SUM_REQ[$POOL]=$(( ${SUM_REQ[$POOL]:-0} + REQ_IN_WIN ))

        if [ "$REQ_IN_WIN" -gt 0 ]; then
            echo "  Busiest 5 minutes (requests | HH:MM) — pinpoints the spike:"
            MIN_STATS=$(printf '%s\n' "$ACC_TMP" \
                | awk '{ if (split($4, a, ":") >= 3) print a[2] ":" a[3] }' \
                | sort | uniq -c | sort -rn)
            echo "$MIN_STATS" | head -5 | sed 's/^/      /'
            [ -z "${HEAVY_MIN[$POOL]}" ] && HEAVY_MIN[$POOL]=$(echo "$MIN_STATS" | head -1 | awk '{print $2" ("$1" req/min)"}')

            echo "  Top 5 client IPs:"
            IP_STATS=$(printf '%s\n' "$ACC_TMP" | awk '{print $1}' | sort | uniq -c | sort -rn)
            echo "$IP_STATS" | head -5 | sed 's/^/      /'
            T_IP=$(echo "$IP_STATS" | head -1 | awk '{print $2}')
            T_IP_C=$(echo "$IP_STATS" | head -1 | awk '{print $1}')
            T_IP_UA=$(printf '%s\n' "$ACC_TMP" | awk -v ip="$T_IP" '$1==ip' \
                      | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -1 \
                      | sed 's/^ *[0-9]* //' | cut -c1-90)
            T_IP_PCT=$(( T_IP_C * 100 / REQ_IN_WIN ))
            echo "      -> heaviest IP $T_IP = ${T_IP_PCT}% of all traffic; UA: ${T_IP_UA:-n/a}"
            if [ -z "${TOP_IP[$POOL]}" ] || [ "$T_IP_C" -gt "${TOP_IP_CNT[$POOL]:-0}" ]; then
                TOP_IP[$POOL]="$T_IP"; TOP_IP_CNT[$POOL]="$T_IP_C"; TOP_IP_UA[$POOL]="$T_IP_UA"
            fi

            echo "  Top 5 requested URIs:"
            URI_STATS=$(printf '%s\n' "$ACC_TMP" | awk -F'"' '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -rn)
            echo "$URI_STATS" | head -5 | sed 's/^/      /'
            if [ -z "${TOP_URI[$POOL]}" ]; then
                TOP_URI[$POOL]=$(echo "$URI_STATS" | head -1 | awk '{print $2}')
                TOP_URI_CNT[$POOL]=$(echo "$URI_STATS" | head -1 | awk '{print $1}')
            fi

            echo "  HTTP status distribution:"
            printf '%s\n' "$ACC_TMP" | awk '{print $9}' | grep -aE '^[0-9]{3}$' \
                | sort | uniq -c | sort -rn | head -5 | sed 's/^/      /'

            # ---- Client profiling: who is hitting us and how ----------------
            echo
            echo "  ${BLD}[client profiling]${RST}"
            echo "  Top user agents:"
            printf '%s\n' "$ACC_TMP" | awk -F'"' '{print $6}' | cut -c1-85 \
                | sort | uniq -c | sort -rn | head -6 | sed 's/^/      /'
            BOT_REQ=$(printf '%s\n' "$ACC_TMP" | awk -F'"' '{print $6}' \
                | grep -aicE 'bot|crawl|spider|slurp|preview|scan|python|curl|wget|go-http|httpclient|headless')
            echo "      -> bot/tool share of traffic: $(( BOT_REQ * 100 / REQ_IN_WIN ))% (${BOT_REQ}/${REQ_IN_WIN} requests)"

            echo
            echo "  Per-IP targeting profile (top 5 IPs):"
            while read -r CNT IP; do
                [ -z "$IP" ] && continue
                IPDATA=$(printf '%s\n' "$ACC_TMP" | awk -v ip="$IP" '$1 == ip')
                N404=$(printf '%s\n' "$IPDATA" | awk '$9 == 404' | grep -ac .)
                IP_UA=$(printf '%s\n' "$IPDATA" | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn \
                        | head -1 | sed 's/^ *[0-9]* //' | cut -c1-60)
                TOP3URI=$(printf '%s\n' "$IPDATA" | awk -F'"' '{print $2}' | awk '{print $2}' \
                        | sort | uniq -c | sort -rn | head -3)
                TOP1URI=$(echo "$TOP3URI" | head -1 | awk '{print $2}')
                P404=$(( N404 * 100 / CNT ))
                # Behaviour classification
                LABEL="BROWSING"
                case "$TOP1URI" in
                    *wp-login*|*xmlrpc*)            LABEL="${RED}BRUTE-FORCE?${RST}" ;;
                    */wp-json/*|*admin-ajax*)       LABEL="${YLW}API/AJAX FLOOD${RST}" ;;
                esac
                [ "$P404" -ge 50 ] && [ "$CNT" -ge 30 ] && LABEL="${RED}SCANNER/PROBE${RST}"
                echo "$IP_UA" | grep -aqiE 'bot|crawl|spider|slurp' && [ "$LABEL" = "BROWSING" ] && LABEL="CRAWLER"
                case "$LABEL" in *BRUTE*|*SCANNER*) SUSP_IPS[$POOL]="${SUSP_IPS[$POOL]}$IP ";; esac

                GEO=$(geo_ip "$IP")
                echo "    ┌────────────────────────────────────────────────────────────────────────"
                printf "    │ %-8s : %s   [%s]\n" "IP"       "$IP" "$LABEL"
                printf "    │ %-8s : %s requests | %s%% 404s | %s%% of window traffic\n" \
                       "Traffic"  "$CNT" "$P404" "$(( CNT * 100 / REQ_IN_WIN ))"
                printf "    │ %-8s : %s\n" "Geo"      "$GEO"
                printf "    │ %-8s : %s\n" "UA"       "${IP_UA:-n/a}"
                FIRSTT=1
                while read -r TC TU; do
                    [ -z "$TU" ] && continue
                    if [ "$FIRSTT" -eq 1 ]; then
                        printf "    │ %-8s : %5s×  %s\n" "Targets" "$TC" "$(echo "$TU" | cut -c1-85)"
                        FIRSTT=0
                    else
                        printf "    │ %-8s   %5s×  %s\n" ""        "$TC" "$(echo "$TU" | cut -c1-85)"
                    fi
                done <<< "$TOP3URI"
                echo "    └────────────────────────────────────────────────────────────────────────"
            done <<< "$(echo "$IP_STATS" | head -5)"
        fi

        # ---- 5b2. php-app.access.log (fpm: duration / memory / %CPU) ---------
        PHPACC="$APP_LOGS/php-app.access.log"
        if [ -r "$PHPACC" ]; then
            echo
            echo "  ${BLD}[php-app.access.log — PHP execution cost]${RST}"
            PHP_TMP=$(read_logs "$PHPACC" | grep -a "\[$D_SLASH:${HH}:")
            PHP_CNT=$(printf '%s' "$PHP_TMP" | grep -ac .)
            SLOW1S=$(printf '%s\n' "$PHP_TMP" | awk '$12+0 >= 1' | grep -ac .)
            TOTSEC=$(printf '%s\n' "$PHP_TMP" | awk '{t+=$12} END {printf "%.0f", t+0}')
            echo "  PHP requests: $PHP_CNT | taking >=1s: $SLOW1S | total PHP time consumed: ${TOTSEC}s"
            PHP_TOTSEC[$POOL]=$(( ${PHP_TOTSEC[$POOL]:-0} + TOTSEC ))
            if [ "$PHP_CNT" -gt 0 ]; then
                echo "  Top 5 slowest PHP requests (duration s | %CPU | URI):"
                SLOWEST=$(printf '%s\n' "$PHP_TMP" \
                    | awk '{uri=$NF; gsub(/"/,"",uri); printf "%8.3f  %7s  %s\n", $12, $14, uri}' \
                    | sort -rn)
                echo "$SLOWEST" | head -5 | cut -c1-120 | sed 's/^/      /'
                if [ -z "${SLOWEST_URI[$POOL]}" ]; then
                    SLOWEST_URI[$POOL]=$(echo "$SLOWEST" | head -1 | awk '{print $3}')
                    SLOWEST_SEC[$POOL]=$(echo "$SLOWEST" | head -1 | awk '{print $1}')
                fi
                echo "  Top 5 URIs by TOTAL PHP time (sum s | hits | URI):"
                printf '%s\n' "$PHP_TMP" \
                    | awk '{uri=$NF; gsub(/"/,"",uri); t[uri]+=$12; c[uri]++}
                           END {for (u in t) printf "%10.1f  %6d  %s\n", t[u], c[u], u}' \
                    | sort -rn | head -5 | sed 's/^/      /'
            fi
        fi

        # ---- 5c. All error logs ----------------------------------------------
        NGX_ERR=$(for f in "$APP_LOGS"/*error.log; do
                      [ -r "$f" ] && read_logs "$f"
                  done | grep -a "^${D_NGX} ${HH}:")
        NGX_ERR_CNT=$(printf '%s' "$NGX_ERR" | grep -ac .)
        PHP_NOISE=$(printf '%s\n' "$NGX_ERR" | grep -ac "FastCGI sent in stderr")
        REAL_ERR=$(printf '%s\n' "$NGX_ERR" | grep -aEc "timed out|Connection refused|resource temporarily unavailable|no live upstreams|worker_connections|access forbidden")
        echo
        echo "  ${BLD}[all *.error.log]${RST} entries: $NGX_ERR_CNT (PHP stderr noise: $PHP_NOISE | timeouts/refused/forbidden: $REAL_ERR)"
        if [ "$REAL_ERR" -gt 0 ]; then
            echo "  Sample critical errors:"
            printf '%s\n' "$NGX_ERR" \
                | grep -aE "timed out|Connection refused|resource temporarily unavailable|no live upstreams|worker_connections|access forbidden" \
                | head -5 | cut -c1-160 | sed 's/^/      /'
        fi
        SUM_ERR[$POOL]=$(( ${SUM_ERR[$POOL]:-0} + REAL_ERR ))

        # ---- 5d. wp-cron (date-aware, falls back to hour-only match) ----------
        CRON_RAW=$(read_logs "$APP_LOGS/wp-cron.log" | grep -a "${HH}:[0-5][0-9]")
        CRON_CNT=$(printf '%s\n' "$CRON_RAW" | grep -aEc "$D_ISO|$D_DASH|$D_SLASH")
        CRON_NOTE=""
        if [ "$CRON_CNT" -eq 0 ]; then
            CRON_CNT=$(printf '%s' "$CRON_RAW" | grep -ac .)
            [ "$CRON_CNT" -gt 0 ] && CRON_NOTE=" (hour-only match; log has no dates)"
        fi
        echo
        echo "  ${BLD}[wp-cron.log]${RST} cron entries in hour ${HH}: ${CRON_CNT}${CRON_NOTE}"
        SUM_CRON[$POOL]=$(( ${SUM_CRON[$POOL]:-0} + CRON_CNT ))
    done
done

###############################################################################
# 6. Cloudways APM tool (read-only usage: --no_upgrade on every call)
###############################################################################
# apm auto-updates itself during execution by default (a disk write), so we
# always pass --no_upgrade to keep this investigation strictly read-only.
run_apm() {   # run_apm <description> <apm args...>
    local desc="$1"; shift
    echo
    echo "  ${BLD}[apm $*]${RST} $desc"
    local out rc
    out=$(timeout 60 apm "$@" --no_upgrade 2>/dev/null)   # capture fully first,
    rc=$?                                                 # then truncate (no SIGPIPE)
    if [ $rc -eq 124 ]; then
        warn "  apm $1 timed out after 60s — skipped."
    elif [ -n "$out" ]; then
        echo "$out" | head -60 | sed 's/^/    /'
        LINES=$(echo "$out" | wc -l)
        [ "$LINES" -gt 60 ] && note "  ...output truncated ($LINES lines total). Rerun manually for full output: apm $* --no_upgrade"
    else
        note "  apm $1 returned no data (rc=$rc) — try: apm $1 --help"
    fi
    return 0
}

section "6. CLOUDWAYS APM SNAPSHOT"
if ! command -v apm >/dev/null 2>&1; then
    note "apm tool not found on this server — skipping (install/usage: Cloudways platform servers only)."
else
    # Log-derived stats: meaningful for today AND useful context for past dates
    for POOL in $POOLS; do
        echo
        echo "${BLD}${YLW}>>> apm stats for app '$POOL' <<<${RST}"
        run_apm "Web traffic statistics"            traffic   -s "$POOL"
        run_apm "Bandwidth by app/url"              bandwidth -s "$POOL"
    done

    # MySQL slow queries targeted at each spike window (works for past dates too;
    # apm date format is DD/MM/YYYY:HH:MM)
    D_APM=$(date -d "$TARGET_DATE" '+%d/%m/%Y')
    for POOL in $POOLS; do
        for HH in $HOURS; do
            run_apm "MySQL SLOW QUERIES during spike window ${HH}:00-${HH}:59" \
                mysql -s "$POOL" -n 5 --slow_queries --from "${D_APM}:${HH}:00" --until "${D_APM}:${HH}:59"
        done
    done

    if [ "$IS_HISTORIC" -eq 0 ]; then
        # Live-state commands: only meaningful while the incident is recent/ongoing
        for POOL in $POOLS; do
            run_apm "MySQL currently running queries"   mysql -s "$POOL" --current_queries
            run_apm "PHP process statistics (current)"  php  -s "$POOL"
            run_apm "Running crons (current)"           cron -s "$POOL"
        done

        echo
        read -rp "Run 'apm scan' for suspicious files? Can take a while but helps rule out malware as the CPU cause [y/N]: " SCAN_ANSW
        case "$SCAN_ANSW" in
            y|Y|yes|YES)
                echo "  ${BLD}[apm scan]${RST} scanning (read-only)..."
                timeout 600 apm scan --no_upgrade 2>/dev/null | head -60 | sed 's/^/    /'
                [ $? -eq 124 ] && warn "  scan timed out after 10 min — run 'apm scan --no_upgrade' manually." ;;
        esac
    else
        note "Skipping apm mysql/php/cron: they report CURRENT state only, which cannot explain a spike on $TARGET_DATE."
    fi
fi

###############################################################################
# 7. atop history
###############################################################################
section "7. ATOP HISTORY ($TARGET_DATE)"
ATOP_FILE="/var/log/atop/atop_${D_ATOP}"
ATOP_TOPPROC=""
if [ ! -r "$ATOP_FILE" ]; then
    warn "atop raw file not found/readable: $ATOP_FILE"
elif ! command -v atopsar >/dev/null 2>&1; then
    warn "atopsar not installed — run manually:  atop -r $ATOP_FILE -b HH:MM"
else
    NCPU=$(nproc 2>/dev/null || echo 1)
    MAX_BUSY=0
    for HH in $HOURS; do
        echo
        echo "${BLD}${YLW}>>> atop window ${HH}:00 - ${HH}:59 <<<${RST}"
        echo
        echo "  ${BLD}Overall CPU busy % per interval (system-wide, ${NCPU} cores):${RST}"
        BUSY_LINES=$(atopsar -c -r "$ATOP_FILE" -b "${HH}:00" -e "${HH}:59" 2>/dev/null \
            | awk '$2 == "all" {
                  tot = 0; for (i = 3; i <= NF; i++) tot += $i
                  idle = $NF
                  if (tot > 0) printf "    %s   busy %3.0f%%   (idle %3.0f%%)\n", $1, (tot-idle)*100/tot, idle*100/tot
              }')
        echo "$BUSY_LINES"
        HB=$(echo "$BUSY_LINES" | grep -oaE 'busy +[0-9]+' | awk '{if ($2+0 > m) m = $2+0} END {print m+0}')
        [ "${HB:-0}" -gt "${MAX_BUSY:-0}" ] && MAX_BUSY=$HB
        echo
        echo "  ${BLD}Top-3 CPU processes per interval:${RST}"
        ATOP_O=$(atopsar -O -r "$ATOP_FILE" -b "${HH}:00" -e "${HH}:59" 2>/dev/null)
        echo "$ATOP_O" | tail -n +5 | head -15 | sed 's/^/    /'
        # Only the FIRST (highest-CPU) process of each interval line counts
        ATOP_TOPPROC="$ATOP_TOPPROC $(echo "$ATOP_O" | awk '$1 ~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}$/ && $3 ~ /^[A-Za-z]/ {print $3}')"
        echo
        echo "  ${BLD}Memory / swap:${RST}"
        atopsar -m -r "$ATOP_FILE" -b "${HH}:00" -e "${HH}:59" 2>/dev/null | tail -n +5 | head -8 | sed 's/^/    /'
    done
    note "Interactive drill-down:  atop -r $ATOP_FILE -b <HH:MM>  (press 't' to step forward, 'm' for memory, 'd' for disk)"
fi
DOMINANT_PROC=$(echo "$ATOP_TOPPROC" | tr ' ' '\n' | sed '/^$/d' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

###############################################################################
# 7B. MySQL slow log (direct, read-only) for the spike windows
###############################################################################
section "7B. MYSQL SLOW LOG ($TARGET_DATE)"
MYSLOW=$(ls /var/log/mysql/*slow*.log 2>/dev/null | head -1)
if [ -z "$MYSLOW" ] || [ ! -r "$MYSLOW" ]; then
    note "MySQL slow log not found/readable under /var/log/mysql — apm mysql output above covers this."
else
    D_OLD=$(date -d "$TARGET_DATE" +%y%m%d)
    for HH in $HOURS; do
        HN=$((10#$HH))
        STATS=$(read_logs "$MYSLOW" | awk -v iso="# Time: ${D_ISO}T${HH}:" -v old="# Time: ${D_OLD}" -v hh=" ${HN}:" '
            /^# Time:/ { inwin = (index($0, iso) == 1) || (index($0, old) == 1 && index($0, hh) > 0) }
            inwin && /^# Query_time:/ { qt = $3 + 0; n++; s += qt; if (qt > mx) mx = qt }
            END { printf "%d %.1f %.1f", n, s, mx }')
        read -r QN QS QM <<< "$STATS"
        echo "  Window ${HH}:00-${HH}:59 — slow queries logged: ${QN:-0} | total time: ${QS:-0}s | slowest: ${QM:-0}s"
    done
    note "Full entries (read-only): grep -A8 '# Time: ${D_ISO}T<HH>' $MYSLOW | less"
fi

###############################################################################
# 8. Root-cause summary (ranked, specific)
###############################################################################
section "8. INVESTIGATION SUMMARY — $TARGET_DATE"

[ -n "$FPM_HITS" ] && warn "php-fpm hit pm.max_children $(echo "$FPM_HITS" | wc -l) time(s) at: $(echo $BREACH_MINUTES | tr '\n' ' ')" \
                   || ok  "No fpm pool exhaustion."
[ -n "$OOM_HITS" ] && warn "oom-killer fired $(echo "$OOM_HITS" | wc -l) time(s) — RAM exhausted." \
                   || ok  "No OOM events."
[ -n "$DOMINANT_PROC" ] && note "Dominant CPU process across spike windows (atop): ${BLD}${DOMINANT_PROC}${RST}"

for POOL in $POOLS; do
    echo
    echo "${BLD}Pool: $POOL${RST}"
    echo "  Slow PHP events in windows      : ${SUM_SLOW[$POOL]:-0}"
    echo "  HTTP requests in windows        : ${SUM_REQ[$POOL]:-0}"
    echo "  Total PHP time consumed         : ${PHP_TOTSEC[$POOL]:-0}s"
    echo "  Real nginx errors in windows    : ${SUM_ERR[$POOL]:-0}"
    echo "  wp-cron entries in windows      : ${SUM_CRON[$POOL]:-0}"
    [ -n "${HEAVY_MIN[$POOL]}" ] && echo "  Busiest minute                  : ${HEAVY_MIN[$POOL]}"
    [ -n "${TOP_MOD[$POOL]}"   ] && echo "  Top module in slow traces       : ${TOP_MOD[$POOL]}"
    [ -n "${TOP_IP[$POOL]}"    ] && echo "  Heaviest IP                     : ${TOP_IP[$POOL]} (${TOP_IP_CNT[$POOL]} req) UA: ${TOP_IP_UA[$POOL]}"
    [ -n "${TOP_URI[$POOL]}"   ] && echo "  Heaviest URI                    : ${TOP_URI[$POOL]} (${TOP_URI_CNT[$POOL]} req)"

    # ---------------- Diagnosis synthesis --------------------------------
    NHOURS=$(echo $HOURS | wc -w); [ "$NHOURS" -lt 1 ] && NHOURS=1
    AVG_CONC=$(( ${PHP_TOTSEC[$POOL]:-0} / (3600 * NHOURS) ))
    echo
    echo "  ${BLD}Diagnosis:${RST}"
    if [ -n "$FPM_HITS" ] && [ "${MAX_BUSY:-0}" -gt 0 ] && [ "${MAX_BUSY:-0}" -lt 60 ]; then
        echo "   ${YLW}WORKER STARVATION — not CPU saturation.${RST} CPU peaked at only ${MAX_BUSY}% while the"
        echo "   pool breached: long-running requests parked workers until the pool filled."
        echo "   Raising pm.max_children or upsizing the server treats the symptom, not the cause."
    elif [ -n "$FPM_HITS" ] && [ "${MAX_BUSY:-0}" -ge 60 ]; then
        echo "   ${RED}CPU SATURATION${RST} — CPU peaked at ${MAX_BUSY}%; the server is genuinely out of"
        echo "   compute during the spike. Optimize the top consumers below or scale up."
    fi
    echo "   Avg concurrently busy PHP workers in window: ~${AVG_CONC} (bursting far higher at the breach minute)."
    [ -n "${SLOWEST_URI[$POOL]}" ] && echo "   Slowest single request: ${SLOWEST_SEC[$POOL]}s — $(echo "${SLOWEST_URI[$POOL]}" | cut -c1-100)"

    echo
    echo "  ${BLD}Ranked findings:${RST}"
    RANK=0

    if [ -n "${SUSP_IPS[$POOL]}" ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} HOSTILE CLIENTS: IP(s) classified as scanner/brute-force in profiling: ${SUSP_IPS[$POOL]}— consider firewall/rate-limit (they burn PHP workers on 404s/login attempts)."
    fi

    case "${SLOWEST_URI[$POOL]}" in
        *add_to_wishlist*|*add-to-cart*)
            RANK=$((RANK+1))
            echo "   ${RED}${RANK}.${RST} CACHE BYPASS: slowest requests carry query strings (add_to_wishlist/add-to-cart) that skip page cache and hit PHP+DB cold for ${SLOWEST_SEC[$POOL]}s. Fix wishlist/cart plugin to use AJAX, or strip/redirect these query strings." ;;
        *wp-admin/edit.php* )
            RANK=$((RANK+1))
            echo "   ${RED}${RANK}.${RST} ADMIN PRODUCT SEARCH: slowest request is a wp-admin product listing/search (${SLOWEST_SEC[$POOL]}s) — LIKE '%term%' scans wp_posts+wp_postmeta with no usable index; consider an indexed search plugin." ;;
    esac

    if [ -n "$OOM_HITS" ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} MEMORY EXHAUSTION: oom-killer fired. Workers*avg-memory exceeds RAM — lower pm.max_children or add RAM before anything else."
    fi

    IP_SHARE=0
    [ "${SUM_REQ[$POOL]:-0}" -gt 0 ] && IP_SHARE=$(( ${TOP_IP_CNT[$POOL]:-0} * 100 / SUM_REQ[$POOL] ))
    if [ "$IP_SHARE" -ge 10 ] && [ "${TOP_IP_CNT[$POOL]:-0}" -ge 100 ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} TRAFFIC CONCENTRATION: ${TOP_IP[$POOL]} alone = ${IP_SHARE}% of requests (UA: ${TOP_IP_UA[$POOL]:-?}). If it's a bot/crawler, rate-limit or block it."
    fi

    case "${TOP_URI[$POOL]}" in
        */admin-ajax.php*|*/wp-json/*|*ajax*)
            RANK=$((RANK+1))
            echo "   ${RED}${RANK}.${RST} AJAX/API FLOOD: heaviest URI is ${TOP_URI[$POOL]} (${TOP_URI_CNT[$POOL]} hits) — uncacheable PHP endpoint hit repeatedly; identify the plugin behind it and throttle/cache it." ;;
    esac

    if [ "${SUM_SLOW[$POOL]:-0}" -gt 50 ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} SLOW PHP: ${SUM_SLOW[$POOL]} slow-script events; most involved module: ${TOP_MOD[$POOL]:-see above} — profile it or check its DB queries."
    fi

    if [ "$DOMINANT_PROC" = "mariadbd" ] || [ "$DOMINANT_PROC" = "mysqld" ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} DATABASE-BOUND: ${DOMINANT_PROC} was the top CPU consumer in atop — slow queries stall PHP workers until max_children is hit. Check the MySQL slow query log (e.g. /var/log/mysql/*slow*)."
    fi

    if [ "${SUM_CRON[$POOL]:-0}" -gt 200 ]; then
        RANK=$((RANK+1))
        echo "   ${RED}${RANK}.${RST} CRON PRESSURE: ${SUM_CRON[$POOL]} wp-cron entries in the windows — review scheduled tasks / consider a real system cron with locking."
    fi

    [ "$RANK" -eq 0 ] && echo "   ${GRN}-${RST} No dominant cause in app logs — inspect atop output above for non-PHP processes (backups, malware scans, updates)."
done

echo
hr
echo "${BLD}NEXT ACTIONS (advice only — nothing was changed by this script):${RST}"
echo "  1. Fix the biggest offender in 'Ranked findings' first, then re-measure."
echo "  2. DATABASE-BOUND? Take the query from 7B / apm --slow_queries, EXPLAIN it, add the missing index."
echo "  3. AJAX/API FLOOD? Throttle or cache the endpoint (plugin settings / nginx rate-limit / block heavy IP)."
echo "  4. CACHE BYPASS? Stop wishlist/cart/UTM query strings from bypassing page cache."
echo "  5. Re-run this script after each change and compare 'Total PHP time consumed'."
hr
ok "Investigation complete. This script made no changes to the server (read-only)."
hr
