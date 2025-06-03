#!/bin/bash
# =========================================================================
# Title:         Analyze Attacks (Consistent & Robust)
# Description:   Advanced log analysis tool for web server attack detection
# Author:        David Carrero Fernández-Baillo <dcarrero@stackscale.com>
# Version:       0.4 beta (English)
# Created:       JUNE 3, 2025
# License:       MIT License
# =========================================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Defaults ---
MIN_THRESHOLD=20
TIME_HOURS=24
LOG_PATH="/home/*/logs/*access*.log"
OUTPUT_FILE="analyze_attacks.log"
SAVE_TO_FILE=false

shopt -s globstar nullglob 2>/dev/null
trap 'echo -e "\n${RED}Interrupted by user. Exiting.${NC}"; exit 1' SIGINT

# ---- Function Definitions ----

show_help() {
cat <<EOF
${CYAN}=================================
        ANALYZE ATTACKS
=================================${NC}
${GREEN}Advanced Web Server Security Log Analysis Tool${NC}
${YELLOW}Author: David Carrero Fernández-Baillo${NC}
${YELLOW}Website: https://carrero.es${NC}
${YELLOW}Version: 0.4 beta${NC}

${GREEN}USAGE:${NC}
  $0 [OPTIONS]

${GREEN}OPTIONS:${NC}
  --help, -h              Show this help message
  --minrequest <number>   Minimum requests (default: 20)
  --hoursago <number>     Hours back to analyze (default: 24)
  --logpath <path>        Custom log path (use quotes if spaces)
  --output <filename>     Output file
  --save                  Save results to file
EOF
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

show_menu() {
	clear
	echo -e "${CYAN}================================="
	echo -e "        ANALYZE ATTACKS"
	echo -e "=================================${NC}"
	echo -e "Date: ${YELLOW}$(date)${NC}"
	echo -e "Attack threshold: ${GREEN}${MIN_THRESHOLD}${NC} requests"
	echo -e "Time window: ${GREEN}${TIME_HOURS}${NC} hours"
	echo -e "Log path: ${CYAN}${LOG_PATH}${NC}"
	if [[ "$SAVE_TO_FILE" == true ]]; then
		echo -e "Save to file: ${GREEN}ENABLED${NC} → ${CYAN}$OUTPUT_FILE${NC}"
	else
		echo -e "Save to file: ${RED}DISABLED${NC}"
	fi

	local log_count=0
	local logs_array=()
	while IFS= read -r log; do logs_array+=("$log"); done < <(expand_logs)
	log_count="${#logs_array[@]}"
	echo -e "Log files found: ${GREEN}${log_count}${NC}"
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
	echo -e "${YELLOW}r/R${NC} Change log path"
	echo -e "${YELLOW}s/S${NC} File saving options"
	echo -e "${RED}0/x/q${NC} Exit"
	echo
	echo -n -e "${YELLOW}Enter your option: ${NC}"
}

change_log_path() {
	echo -e "\n${CYAN}=== CHANGE LOG PATH ===${NC}"
	echo -e "${YELLOW}Current: ${GREEN}$LOG_PATH${NC}\n"
	echo -e "${GREEN}Select a log path option:${NC}"
	echo -e "1. RunCloud:      /home/*/logs/*access*.log"
	echo -e "2. Plesk:         /var/www/vhosts/*/logs/*access*.log"
	echo -e "3. cPanel:        /usr/local/apache/domlogs/*"
	echo -e "4. Apache2:       /var/log/apache2/*access*.log"
	echo -e "5. Nginx:         /var/log/nginx/*access*.log"
	echo -e "6. Custom path"
	echo -e "7. Keep current"
	echo
	echo -n -e "${YELLOW}Select option 1-7: ${NC}"
	read -r choice
	case $choice in
		1) LOG_PATH="/home/*/logs/*access*.log" ;;
		2) LOG_PATH="/var/www/vhosts/*/logs/*access*.log" ;;
		3) LOG_PATH="/usr/local/apache/domlogs/*" ;;
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

analyze_ips_by_pattern() {
	local pattern="$1"
	local label="$2"
	local status="$3"   # status code to filter, may be empty

	mapfile -t logs < <(get_time_filtered_logs "$TIME_HOURS")
	if [[ ${#logs[@]} -eq 0 ]]; then
		echo -e "${RED}No log files found for analysis.${NC}"
		return
	fi
	echo -e "\n${CYAN}=== $label ===${NC}"
	echo -e "${YELLOW}User             IP Address                        Requests${NC}"
	echo    "-----------------------------------------------------------"

	local results
	if [[ -z "$pattern" && -z "$status" ]]; then
		results=$(awk -v threshold="$MIN_THRESHOLD" '
		{ split(FILENAME, parts, "/"); user=parts[3]; ip=$1; cnt[user "|" ip]++ }
		END { for (k in cnt) { if(cnt[k]>=threshold){split(k,a,"|"); printf "%-15s %-32s %d\n",a[1],a[2],cnt[k]} } }' "${logs[@]}" | sort -k3 -nr | head -15)
	else
		grep_opts=()
		[[ -n "$pattern" ]] && grep_opts+=(-iE "$pattern")
		results=$(grep "${grep_opts[@]}" "${logs[@]}" 2>/dev/null | awk -v threshold="$MIN_THRESHOLD" -v status="$status" '
		{
			split(FILENAME, parts, "/")
			user=(length(parts)>3)?parts[3]:"unknown"
			ip=$1
			if (status=="" || $9==status) cnt[user "|" ip]++
		}
		END {
			for (k in cnt) {
				if (cnt[k] >= threshold) {
					split(k, a, "|")
					printf "%-15s %-32s %d\n", a[1], a[2], cnt[k]
				}
			}
		}' | sort -k3 -nr)
	fi
	[[ -z "$results" ]] && results="No data found."
	echo "$results"
	save_output "=== $label ===\n$results\n"
	echo -e "\n${GREEN}Analysis completed${NC}"
}

analyze_top_ips()                { analyze_ips_by_pattern "" "TOP ACTIVE IPs"; }
analyze_malicious_bots()         { analyze_ips_by_pattern "scrapy|python|curl|wget|bot" "MALICIOUS BOTS"; }
analyze_wordpress_attacks()      { analyze_ips_by_pattern "wp-login|xmlrpc" "WORDPRESS ATTACKS"; }
analyze_404_errors()             { analyze_ips_by_pattern "" "404 ERRORS" "404"; }
analyze_403_errors()             { analyze_ips_by_pattern "" "403 ERRORS" "403"; }
analyze_injection_attempts()     { analyze_ips_by_pattern "union|select|script|javascript|eval" "INJECTION ATTEMPTS"; }
analyze_activity()               { analyze_top_ips; }

analyze_all() {
	echo -e "\n${RED}=== COMPLETE ANALYSIS ===${NC}"
	analyze_top_ips
	analyze_malicious_bots
	analyze_wordpress_attacks
	analyze_404_errors
	analyze_403_errors
	analyze_injection_attempts
	echo -e "\n${RED}=== ANALYSIS FINISHED ===${NC}"
}

# ---- Argument Parsing ----
# Only parse arguments if there are any!
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
			--output) OUTPUT_FILE="$2"; shift 2 ;;
			--save) SAVE_TO_FILE=true; shift ;;
			*) echo -e "${RED}Unknown option: $1${NC}"; echo "Use --help for usage information."; exit 1 ;;
		esac
	done
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
		r|R) change_log_path ;;
		s|S) toggle_file_saving ;;
		0|x|X|q|Q)
			[[ "$SAVE_TO_FILE" == true && -f "$OUTPUT_FILE" ]] && echo -e "\n${GREEN}Results saved to: ${CYAN}$OUTPUT_FILE${NC}"
			echo -e "\n${GREEN}Goodbye!${NC}"; exit 0 ;;
		*) echo -e "\n${RED}Invalid option${NC}"; sleep 1 ;;
	esac
done
