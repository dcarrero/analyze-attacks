#!/bin/bash
# =========================================================================
# Title:         Analyze Attacks
# Description:   Advanced log analysis tool for web server attack detection
# Author:        David Carrero Fernández-Baillo <dcarrero@stackscale.com>
# Version:       0.9 beta (English)
# Created:       JUNE 2025
# License:       MIT License
# =========================================================================

export LC_ALL=en_US.UTF-8

# --- Colors (ANSI) ---
CYAN=$'\e[0;36m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
RED=$'\e[0;31m'
NC=$'\e[0m'

# --- Defaults ---
MIN_THRESHOLD=20
TIME_HOURS=24
LOG_PATH="/home/*/logs/*access*.log"
ERROR_LOG_PATH="/home/*/logs/*error*.log"
OUTPUT_FILE="analyze_attacks.log"
SAVE_TO_FILE=false

# Default error log candidates (ordered by preference)
ERROR_LOG_CANDIDATES=(
    "/home/*/logs/*error*.log"                  # RunCloud
    "/var/www/vhosts/*/logs/error_log"          # Plesk
    "/usr/local/apache/domlogs/*error_log*"      # cPanel
    "/var/log/apache2/error.log"                # Apache2
    "/var/log/nginx/error.log"                  # Nginx
)

shopt -s globstar nullglob 2>/dev/null
trap 'echo -e "\n${RED}Interrupted by user. Exiting.${NC}"; exit 1' SIGINT

# ---- Function Definitions ----

show_help() {
    printf "%b\n" "${CYAN}================================="
    printf "%b\n" "        ANALYZE ATTACKS"
    printf "%b\n" "=================================${NC}"
    printf "%b\n" "${GREEN}Advanced Web Server Security Log Analysis Tool${NC}"
    printf "%b\n" "${YELLOW}Author: David Carrero Fernández-Baillo${NC}"
    printf "%b\n" "${YELLOW}Website: https://carrero.es${NC}"
    printf "%b\n" "${YELLOW}Version: 0.9 beta${NC}"
    printf "\n"
    printf "%b\n" "${GREEN}USAGE:${NC}"
    printf "%b\n" "  $0 [OPTIONS]"
    printf "\n"
    printf "%b\n" "${GREEN}OPTIONS:${NC}"
    printf "%b\n" "  --help, -h              Show this help message"
    printf "%b\n" "  --minrequest <number>   Minimum requests (default: 20)"
    printf "%b\n" "  --hoursago <number>     Hours back to analyze (default: 24)"
    printf "%b\n" "  --logpath <path>        Custom access log path (use quotes if spaces)"
    printf "%b\n" "  --errorlog <path>       Custom error_log path (wildcards supported)"
    printf "%b\n" "  --output <filename>     Output file"
    printf "%b\n" "  --save                  Save results to file"
    exit 0
}

save_output() {
    local content="$1"
    if [[ "$SAVE_TO_FILE" == true ]]; then
        echo -e "$content" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
        echo -e "${GREEN}✓ Results saved to: ${CYAN}$OUTPUT_FILE${NC}"
    fi
}

pause() {
    [[ -z "$NOPAUSE" ]] && { echo; echo -n -e "${YELLOW}Press Enter to continue...${NC}"; read -r; }
}

expand_logs() {
    local globbed=()
    while IFS= read -r -d '' file; do
        [[ -f "$file" ]] && globbed+=("$file")
    done < <(find $(eval echo "$LOG_PATH") -type f -print0 2>/dev/null)
    printf '%s\n' "${globbed[@]}"
}

get_time_filtered_logs() {
    local hours_ago="$1"
    local filtered=()
    while IFS= read -r -d '' file; do
        [[ -f "$file" ]] && filtered+=("$file")
    done < <(find $(eval echo "$LOG_PATH") -type f -newermt "${hours_ago} hours ago" -print0 2>/dev/null)
    printf '%s\n' "${filtered[@]}"
}

expand_error_logs() {
    local globbed=()
    local pattern="${ERROR_LOG_PATH:-}"
    [[ -z "$pattern" ]] && return 1
    while IFS= read -r -d '' file; do
        [[ -f "$file" ]] && globbed+=("$file")
    done < <(find $(eval echo "$pattern") -type f -print0 2>/dev/null)
    printf '%s\n' "${globbed[@]}"
}

autodetect_error_log_path() {
    for candidate in "${ERROR_LOG_CANDIDATES[@]}"; do
        local found=()
        while IFS= read -r -d '' f; do found+=("$f"); done < <(find $(eval echo "$candidate") -type f -print0 2>/dev/null)
        if [[ ${#found[@]} -gt 0 ]]; then
            ERROR_LOG_PATH="$candidate"
            return 0
        fi
    done
    ERROR_LOG_PATH=""
    return 1
}

show_menu() {
    clear
    echo -e "${CYAN}================================="
    echo -e "        ANALYZE ATTACKS"
    echo -e "=================================${NC}"
    echo -e "Date: ${YELLOW}$(date)${NC}"
    echo -e "Attack threshold: ${GREEN}${MIN_THRESHOLD}${NC} requests"
    echo -e "Time window: ${GREEN}${TIME_HOURS}${NC} hours"
    echo -e "Access log path: ${CYAN}${LOG_PATH}${NC}"
    if [[ "$ERROR_LOG_PATH" != "" ]]; then
        echo -e "Error log path: ${CYAN}${ERROR_LOG_PATH}${NC}"
        local errorlog_count=0
        local error_logs=()
        while IFS= read -r f; do error_logs+=("$f"); done < <(expand_error_logs)
        errorlog_count="${#error_logs[@]}"
        echo -e "Error log files found: ${GREEN}${errorlog_count}${NC}"
    fi
    if [[ "$SAVE_TO_FILE" == true ]]; then
        echo -e "Save to file: ${GREEN}ENABLED${NC} → ${CYAN}$OUTPUT_FILE${NC}"
    else
        echo -e "Save to file: ${RED}DISABLED${NC}"
    fi
    local log_count=0
    local logs_array=()
    while IFS= read -r log; do logs_array+=("$log"); done < <(expand_logs)
    log_count="${#logs_array[@]}"
    echo -e "Access log files found: ${GREEN}${log_count}${NC}"
    echo
    echo -e "${GREEN}Select an option:${NC}"
    echo -e "1. Top active IPs"
    echo -e "2. Detect malicious bots"
    echo -e "3. WordPress attacks"
    echo -e "4. Suspicious 404 errors"
    echo -e "5. 403 errors - blocked IPs"
    echo -e "6. SQL Injection/XSS attempts"
    echo -e "7. Activity in time window"
    echo -e "8. Complete analysis"
    echo -e "9. Analyze error_log"
    echo -e "${YELLOW}r/R${NC} Change access log path"
    echo -e "${YELLOW}e/E${NC} Change error_log path"
    echo -e "${YELLOW}s/S${NC} File saving options"
    echo -e "${RED}0/x/q${NC} Exit"
    echo
    echo -n -e "${YELLOW}Enter your option: ${NC}"
}

change_log_path() {
    echo -e "\n${CYAN}=== CHANGE ACCESS LOG PATH ===${NC}"
    echo -e "${YELLOW}Current: ${GREEN}$LOG_PATH${NC}\n"
    echo -e "${GREEN}Select a log path option:${NC}"
    echo -e "1. RunCloud:      /home/*/logs/*access*.log"
    echo -e "2. Plesk:         /var/www/vhosts/*/logs/access*_log*"
    echo -e "3. cPanel:        /usr/local/apache/domlogs/*access_log*"
    echo -e "4. Apache2:       /var/log/apache2/*access*.log"
    echo -e "5. Nginx:         /var/log/nginx/*access*.log"
    echo -e "6. Custom path"
    echo -e "7. Keep current"
    echo
    echo -n -e "${YELLOW}Select option 1-7: ${NC}"
    read -r choice
    case $choice in
        1) LOG_PATH="/home/*/logs/*access*.log" ;;
        2) LOG_PATH="/var/www/vhosts/*/logs/access*_log*" ;;
        3) LOG_PATH="/usr/local/apache/domlogs/*access_log*" ;;
        4) LOG_PATH="/var/log/apache2/*access*.log" ;;
        5) LOG_PATH="/var/log/nginx/*access*.log" ;;
        6)
            echo -n -e "${YELLOW}Enter custom path: ${NC}"
            read -r custom_path
            [[ -n "$custom_path" ]] && LOG_PATH="$custom_path"
            ;;
        *) ;;
    esac
    echo -e "${GREEN}Current log path: ${CYAN}$LOG_PATH${NC}"
    sleep 1
}

change_error_log_path() {
    echo -e "\n${CYAN}=== CHANGE ERROR LOG PATH ===${NC}"
    echo -e "${YELLOW}Current: ${GREEN}${ERROR_LOG_PATH:-unset}${NC}\n"
    echo -e "${GREEN}Select an error log path option:${NC}"
    echo -e "1. RunCloud:      /home/*/logs/*error*.log"
    echo -e "2. Plesk:         /var/www/vhosts/*/logs/error_log"
    echo -e "3. cPanel:        /usr/local/apache/domlogs/*error_log*"
    echo -e "4. Apache2:       /var/log/apache2/error.log"
    echo -e "5. Nginx:         /var/log/nginx/error.log"
    echo -e "6. Custom path"
    echo -e "7. Keep current"
    echo
    echo -n -e "${YELLOW}Select option 1-7: ${NC}"
    read -r choice
    case $choice in
        1) ERROR_LOG_PATH="/home/*/logs/*error*.log" ;;
        2) ERROR_LOG_PATH="/var/www/vhosts/*/logs/error_log" ;;
        3) ERROR_LOG_PATH="/usr/local/apache/domlogs/*error_log*" ;;
        4) ERROR_LOG_PATH="/var/log/apache2/error.log" ;;
        5) ERROR_LOG_PATH="/var/log/nginx/error.log" ;;
        6)
            echo -n -e "${YELLOW}Enter custom error log path: ${NC}"
            read -r custom_path
            [[ -n "$custom_path" ]] && ERROR_LOG_PATH="$custom_path"
            ;;
        *) ;;
    esac
    echo -e "${GREEN}Current error_log path: ${CYAN}$ERROR_LOG_PATH${NC}"
    sleep 1
}

analyze_top_ips() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== TOP ACTIVE IPs ===${NC}"
    echo -e "${YELLOW}IP                Requests   Example User-Agent${NC}"
    echo    "----------------------------------------------------------------------------"
    local results
    results=$(awk -F'"' '
        {
            split($1, a, " ")
            ip = a[1]
            ua = $6
            if (ua == "" || ua ~ /^ *$/) ua = "-"
            if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
                count[ip "|" ua]++
        }
        END {
            for (k in count)
                if (count[k] >= ENVIRON["MIN_THRESHOLD"]) {
                    split(k, b, "|")
                    printf "%-18s %7d   %s\n", b[1], count[k], b[2]
                }
        }
    ' "${logs[@]}" | sort -k2 -nr | head -20)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== TOP ACTIVE IPs ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_malicious_bots() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== MALICIOUS BOTS (by IP and User-Agent) ===${NC}"
    echo -e "${YELLOW}IP                Requests   User-Agent${NC}"
    echo    "----------------------------------------------------------------------------"
    local results
    results=$(grep -aiE "scrapy|python|curl|wget|bot" "${logs[@]}" 2>/dev/null |
        awk -F'"' -v threshold="$MIN_THRESHOLD" '
        {
            split($1, a, " ")
            ip = a[1]
            ua = $6
            if (ua == "" || ua ~ /^ *$/) ua = "-"
            key = ip "|" ua
            count[key]++
        }
        END {
            for (k in count) {
                if (count[k] >= threshold) {
                    split(k, b, "|")
                    printf "%-18s %7d   %s\n", b[1], count[k], b[2]
                }
            }
        }' | sort -k2 -nr)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== MALICIOUS BOTS ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_wordpress_attacks() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== WORDPRESS ATTACKS (Type, IP, UA) ===${NC}"
    echo -e "${YELLOW}Type         IP                Requests   Example UA${NC}"
    echo    "--------------------------------------------------------------------------------------"
    local results
    results=$(grep -aiE "wp-login|xmlrpc|wp-cron|admin-ajax|wp-json" "${logs[@]}" 2>/dev/null |
        awk -F'"' -v threshold="$MIN_THRESHOLD" '
        {
            split($1, a, " ")
            ip = a[1]
            req = $2
            ua = $6
            type = (req ~ /wp-login/) ? "wp-login" :
                   (req ~ /xmlrpc/) ? "xmlrpc" :
                   (req ~ /wp-cron/) ? "wp-cron" :
                   (req ~ /admin-ajax/) ? "admin-ajax" :
                   (req ~ /wp-json/) ? "wp-json" : "other"
            key = type "|" ip "|" ua
            count[key]++
        }
        END {
            for (k in count) {
                if (count[k] >= threshold) {
                    split(k, b, "|")
                    printf "%-12s %-18s %7d   %s\n", b[1], b[2], count[k], b[3]
                }
            }
        }' | sort -k3 -nr)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== WORDPRESS ATTACKS ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_404_errors() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== 404 ERRORS (by IP) ===${NC}"
    echo -e "${YELLOW}IP                Requests   Unique URLs   Example URL${NC}"
    echo    "----------------------------------------------------------------------------"
    local results
    results=$(awk '
        $9 == 404 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            ip = $1
            url = $7
            count[ip]++
            if (!(ip in example_url)) example_url[ip] = url
            unique_url[ip][url] = 1
        }
        END {
            for (ip in count)
                if (count[ip] >= ENVIRON["MIN_THRESHOLD"]) {
                    n_url = length(unique_url[ip])
                    printf "%-18s %7d   %11d   %s\n", ip, count[ip], n_url, example_url[ip]
                }
        }' "${logs[@]}" | sort -k2 -nr)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== 404 ERRORS ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_403_errors() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== 403 ERRORS (by IP) ===${NC}"
    echo -e "${YELLOW}IP                Requests   Unique URLs   Example URL${NC}"
    echo    "----------------------------------------------------------------------------"
    local results
    results=$(awk '
        $9 == 403 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            ip = $1
            url = $7
            count[ip]++
            if (!(ip in example_url)) example_url[ip] = url
            unique_url[ip][url] = 1
        }
        END {
            for (ip in count)
                if (count[ip] >= ENVIRON["MIN_THRESHOLD"]) {
                    n_url = length(unique_url[ip])
                    printf "%-18s %7d   %11d   %s\n", ip, count[ip], n_url, example_url[ip]
                }
        }' "${logs[@]}" | sort -k2 -nr)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== 403 ERRORS ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_injection_attempts() {
    mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
    if [[ ${#logs[@]} -eq 0 ]]; then
        echo -e "${RED}No log files found for analysis.${NC}"
        return
    fi
    echo -e "\n${CYAN}=== INJECTION ATTEMPTS ===${NC}"
    echo -e "${YELLOW}IP                Requests   Example Path${NC}"
    echo    "----------------------------------------------------------------------------"
    local results
    results=$(grep -aiE "union|select|script|javascript|eval" "${logs[@]}" 2>/dev/null |
        awk -F'"' '
        {
            split($1, a, " ")
            ip = a[1]
            req = $2
            count[ip "|" req]++
        }
        END {
            for (k in count)
                if (count[k] >= ENVIRON["MIN_THRESHOLD"]) {
                    split(k, b, "|")
                    printf "%-18s %7d   %s\n", b[1], count[k], b[2]
                }
        }' | sort -k2 -nr)
    [[ -z "$results" ]] && results="No data found."
    echo "$results"
    save_output "=== INJECTION ATTEMPTS ===\n$results\n"
    echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_activity() { analyze_top_ips; }

analyze_error_log() {
    echo -e "\n${CYAN}=== ERROR LOG ANALYSIS ===${NC}"
    local error_logs=()
    while IFS= read -r f; do error_logs+=("$f"); done < <(expand_error_logs)
    if [[ ${#error_logs[@]} -eq 0 ]]; then
        echo -e "${RED}No error log files found for analysis.${NC}"
        return
    fi
    echo -e "${YELLOW}Top 10 error messages (all error logs):${NC}"
    for errfile in "${error_logs[@]}"; do
        echo -e "${CYAN}File: $errfile${NC}"
        if grep -q '^\[' "$errfile"; then
            awk -F'[][:]' '
                {
                    type = $5;
                    sub(/^[ ]+/, "", type);
                    msg = $0;
                    sub(/^\[[^]]+\] \[[^]]+\] \[[^]]+\] /, "", msg);
                    count[type "|" msg]++;
                }
                END {
                    for (k in count)
                        print count[k], k
                }
            ' "$errfile" | sort -nr | head -10 | awk -F'|' '{printf "%-5s %-20s %s\n", $1, $2, $3}'
        else
            awk '
                match($0, /\[(ERROR|WARN|NOTICE|INFO)\]/, m) {
                    type = m[1];
                    msg = $0;
                    sub(/^[0-9\-\:\. \[\]]+/, "", msg);
                    gsub(/\[[^]]*\]/, "", msg);
                    sub(/^[ ]+/, "", msg);
                    count[type "|" msg]++;
                }
                END {
                    for (k in count)
                        print count[k], k
                }
            ' "$errfile" | sort -nr | head -10 | awk -F'|' '{printf "%-5s %-8s %s\n", $1, $2, $3}'
        fi
    done
    echo -e "${GREEN}Analysis completed${NC}"
}

analyze_all() {
    echo -e "\n${RED}=== COMPLETE ANALYSIS ===${NC}"
    analyze_top_ips
    analyze_malicious_bots
    analyze_wordpress_attacks
    analyze_404_errors
    analyze_403_errors
    analyze_injection_attempts
    if [[ -n "$ERROR_LOG_PATH" ]]; then
        analyze_error_log
    fi
    echo -e "\n${RED}=== ANALYSIS FINISHED ===${NC}"
}

toggle_file_saving() {
    echo -e "\n${CYAN}=== FILE SAVING OPTIONS ===${NC}"
    echo -e "${YELLOW}Current status:${NC}"
    if [[ "$SAVE_TO_FILE" == true ]]; then
        echo -e "  Save to file: ${GREEN}ENABLED${NC}"
    else
        echo -e "  Save to file: ${RED}DISABLED${NC}"
    fi
    echo -e "  Output file: ${CYAN}$OUTPUT_FILE${NC}"
    echo -e "\n${GREEN}Options:${NC}"
    echo -e "1. Toggle saving on/off"
    echo -e "2. Change output filename"
    echo -e "3. Keep current settings"
    echo
    echo -n -e "${YELLOW}Select option 1-3: ${NC}"
    read -r choice
    case $choice in
        1)
            SAVE_TO_FILE=$([ "$SAVE_TO_FILE" == true ] && echo false || echo true)
            ;;
        2)
            echo -n -e "${YELLOW}Enter new filename: ${NC}"
            read -r new_filename
            [[ -n "$new_filename" ]] && OUTPUT_FILE="$new_filename"
            ;;
        *) ;;
    esac
    sleep 1
}

# ---- Argument Parsing ----
if [[ $# -gt 0 ]]; then
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) show_help ;;
            --minrequest|--threshold)
                [[ -z "$2" || ! "$2" =~ ^[0-9]+$ ]] && { echo -e "${RED}Error: invalid value for --minrequest${NC}"; exit 1; }
                MIN_THRESHOLD="$2"; shift 2 ;;
            --hoursago|--hours)
                [[ -z "$2" || ! "$2" =~ ^[0-9]+$ ]] && { echo -e "${RED}Error: invalid value for --hoursago${NC}"; exit 1; }
                TIME_HOURS="$2"; shift 2 ;;
            --logpath) LOG_PATH="$2"; shift 2 ;;
            --errorlog) ERROR_LOG_PATH="$2"; shift 2 ;;
            --output) OUTPUT_FILE="$2"; shift 2 ;;
            --save) SAVE_TO_FILE=true; shift ;;
            *) echo -e "${RED}Unknown option: $1${NC}"; echo "Use --help for usage information."; exit 1 ;;
        esac
    done
fi

# Autodetect error_log path if unset
if [[ -z "$ERROR_LOG_PATH" ]]; then
    autodetect_error_log_path
fi

# ---- Main Loop ----
while true; do
    show_menu
    read -r choice
    case $choice in
        1) analyze_top_ips; pause ;;
        2) analyze_malicious_bots; pause ;;
        3) analyze_wordpress_attacks; pause ;;
        4) analyze_404_errors; pause ;;
        5) analyze_403_errors; pause ;;
        6) analyze_injection_attempts; pause ;;
        7) analyze_activity; pause ;;
        8) analyze_all; pause ;;
        9) analyze_error_log; pause ;;
        r|R) change_log_path ;;
        e|E) change_error_log_path ;;
        s|S) toggle_file_saving ;;
        0|x|X|q|Q)
            [[ "$SAVE_TO_FILE" == true && -f "$OUTPUT_FILE" ]] && echo -e "\n${GREEN}Results saved to: ${CYAN}$OUTPUT_FILE${NC}"
            echo -e "\n${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "\n${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
