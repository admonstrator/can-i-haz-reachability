#!/bin/sh
# shellcheck shell=ash
# Description: Temporarily opens firewall ports for testing router reachability
# Author: Admon

SCRIPT_VERSION="2026.01.08.10"
SCRIPT_NAME="test.sh"
TIMEOUT=300  # 5 minutes timeout
PORTS="80,443"  # Default ports to test
AUTO_TEST=0  # Automatic test mode (no user interaction)
DEBUG=0  # Debug mode (show raw JSON responses)
REFLECTOR_URL="https://reflector.example.com/check"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "ERROR")
            printf "${RED}[ERROR]${NC} %s\n" "$message" >&2
            ;;
        "SUCCESS")
            printf "${GREEN}[SUCCESS]${NC} %s\n" "$message"
            ;;
        "WARNING")
            printf "${YELLOW}[WARNING]${NC} %s\n" "$message"
            ;;
        "INFO")
            printf "${BLUE}[INFO]${NC} %s\n" "$message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
}

# Check if firewall rule exists
check_firewall_rule_exists() {
    local family="$1"  # ipv4 or ipv6
    uci show firewall | grep -q "firewall.reflector_test_${family}"
    return $?
}

# Get current state of firewall rule (if it exists)
get_firewall_rule_state() {
    local family="$1"  # ipv4 or ipv6
    if check_firewall_rule_exists "$family"; then
        enabled=$(uci -q get firewall.reflector_test_${family}.enabled)
        if [ "$enabled" = "1" ]; then
            return 0  # enabled
        else
            return 1  # disabled
        fi
    else
        return 2  # does not exist
    fi
}

# Create and enable firewall rule
open_firewall() {
    local ports="$1"
    local ports_spaces=$(echo "$ports" | tr ',' ' ')
    
    # Create/update IPv4 rule
    if check_firewall_rule_exists "ipv4"; then
        log "WARNING" "Firewall rule 'reflector_test_ipv4' already exists"
        uci set firewall.reflector_test_ipv4.enabled='1'
        uci set firewall.reflector_test_ipv4.dest_port="$ports_spaces"
    else
        uci set firewall.reflector_test_ipv4=rule
        uci set firewall.reflector_test_ipv4.dest_port="$ports_spaces"
        uci set firewall.reflector_test_ipv4.proto='tcp'
        uci set firewall.reflector_test_ipv4.name='Reflector-Test-IPv4'
        uci set firewall.reflector_test_ipv4.target='ACCEPT'
        uci set firewall.reflector_test_ipv4.src='wan'
        uci set firewall.reflector_test_ipv4.family='ipv4'
        uci set firewall.reflector_test_ipv4.enabled='1'
    fi
    
    # Create/update IPv6 rule
    if check_firewall_rule_exists "ipv6"; then
        log "WARNING" "Firewall rule 'reflector_test_ipv6' already exists"
        uci set firewall.reflector_test_ipv6.enabled='1'
        uci set firewall.reflector_test_ipv6.dest_port="$ports_spaces"
    else
        uci set firewall.reflector_test_ipv6=rule
        uci set firewall.reflector_test_ipv6.dest_port="$ports_spaces"
        uci set firewall.reflector_test_ipv6.proto='tcp'
        uci set firewall.reflector_test_ipv6.name='Reflector-Test-IPv6'
        uci set firewall.reflector_test_ipv6.target='ACCEPT'
        uci set firewall.reflector_test_ipv6.src='wan'
        uci set firewall.reflector_test_ipv6.family='ipv6'
        uci set firewall.reflector_test_ipv6.enabled='1'
    fi
    
    uci commit firewall
    
    log "INFO" "Restarting firewall..."
    /etc/init.d/firewall restart >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        log "SUCCESS" "Firewall opened successfully for ports: $ports"
        return 0
    else
        log "ERROR" "Failed to restart firewall"
        return 1
    fi
}

# Delete firewall rules
close_firewall() {
    log "INFO" "Removing firewall rules..."
    local changed=0
    
    # Remove IPv4 rule if exists
    if check_firewall_rule_exists "ipv4"; then
        uci delete firewall.reflector_test_ipv4 2>/dev/null
        changed=1
    fi
    
    # Remove IPv6 rule if exists
    if check_firewall_rule_exists "ipv6"; then
        uci delete firewall.reflector_test_ipv6 2>/dev/null
        changed=1
    fi
    
    if [ $changed -eq 0 ]; then
        log "INFO" "Firewall rules do not exist"
        return 0
    fi
    
    uci commit firewall
    
    log "INFO" "Restarting firewall..."
    /etc/init.d/firewall restart >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        log "SUCCESS" "Firewall rules removed successfully"
        return 0
    else
        log "ERROR" "Failed to restart firewall"
        return 1
    fi
}

# Remove firewall rules completely (alias for close_firewall)
remove_firewall_rule() {
    close_firewall
}

# Parse JSON response (simple parser for ash)
parse_json_result() {
    local json="$1"
    local port="$2"
    
    # Extract reachable status for the specific port
    echo "$json" | grep -o "\"$port\":{[^}]*}" | grep -o '"reachable":[^,}]*' | cut -d':' -f2
}

# Extract latency from JSON
get_latency() {
    local json="$1"
    local port="$2"
    
    echo "$json" | grep -o "\"$port\":{[^}]*}" | grep -o '"latency_ms":[0-9]*' | cut -d':' -f2
}

# Check if port has TLS info
has_tls_info() {
    local json="$1"
    local port="$2"
    
    echo "$json" | grep -o "\"$port\":{.*\"tls\":{" >/dev/null 2>&1
    return $?
}

# Extract TLS version
get_tls_version() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"tls\":{.*\"version\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Extract cipher suite
get_cipher_suite() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"cipher_suite\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Extract certificate subject
get_cert_subject() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"certificate\":{.*\"subject\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Check if certificate is self-signed
is_cert_self_signed() {
    local json="$1"
    local port="$2"
    
    echo "$json" | grep -o "\"$port\":{.*\"self_signed\":true" >/dev/null 2>&1
    return $?
}

# Get days until expiry
get_cert_days_until_expiry() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"days_until_expiry\":\\([0-9-]*\\).*/\\1/p"
}

# Get TLS warnings
get_tls_warnings() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"warnings\":\\[\\(.*\\)\\].*/\\1/p" | tr -d '"' | tr ',' '\n'
}

# Check if port has SSH info
has_ssh_info() {
    local json="$1"
    local port="$2"
    
    # Check if the port object contains a banner field starting with SSH
    # This is a simpler approach that works with the flat JSON structure
    echo "$json" | grep -o "\"$port\":{[^}]*}" | grep -q '"banner":"SSH-'
    return $?
}

# Extract SSH banner
get_ssh_banner() {
    local json="$1"
    local port="$2"
    
    # Extract the port object and then get the banner field
    echo "$json" | grep -o "\"$port\":{[^}]*}" | sed -n 's/.*"banner":"\([^"]*\)".*/\1/p'
}

# Extract SSH protocol
get_ssh_protocol() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"ssh\":{.*\"protocol\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Extract SSH software
get_ssh_software() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"ssh\":{.*\"software\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Extract SSH host key algo
get_ssh_host_key_algo() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"host_key_algo\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Get SSH warnings
get_ssh_warnings() {
    local json="$1"
    local port="$2"
    
    echo "$json" | sed -n "s/.*\"$port\":{.*\"ssh\":{.*\"warnings\":\\[\\(.*\\)\\].*/\\1/p" | tr -d '"' | tr ',' '\n'
}

# Extract client IP from JSON
get_client_ip() {
    local json="$1"
    echo "$json" | grep -o '"client_ip":"[^"]*"' | cut -d'"' -f4
}

# Run automatic test
run_auto_test() {
    local ports="$1"
    
    log "INFO" "Running automatic reachability test..."
    echo ""
    
    # Wait a moment for firewall to be fully applied
    sleep 2
    
    # Build URL with ports (enable TLS analysis)
    local test_url="${REFLECTOR_URL}?ports=${ports}&tls_analyze=true"
    
    # Test both IPv4 and IPv6
    local has_ipv4=0
    local has_ipv6=0
    local response_v4=""
    local response_v6=""
    local client_ip_v4=""
    local client_ip_v6=""
    
    # Try IPv4 first (bypass VPN if active)
    log "INFO" "Testing IPv4 connectivity..."
    response_v4=$(sudo -g nonevpn curl -4 -sSL --max-time 30 "$test_url" 2>/dev/null || curl -4 -sSL --max-time 30 "$test_url" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$response_v4" | grep -q '"client_ip"'; then
        # Check for rate limit
        if echo "$response_v4" | grep -q '"error".*"rate_limit'; then
            log "ERROR" "Rate limit exceeded on reflector service"
            echo ""
            printf "  ${RED}Too many requests to the reflector service.${NC}\n"
            echo "  Please wait a few minutes before trying again."
            echo ""
            return 1
        fi
        
        has_ipv4=1
        client_ip_v4=$(get_client_ip "$response_v4")
        log "SUCCESS" "IPv4 test successful"
        
        # Debug mode: show raw response
        if [ "$DEBUG" -eq 1 ]; then
            echo ""
            printf "${YELLOW}[DEBUG] IPv4 Response:${NC}\n"
            echo "$response_v4" | sed 's/,/,\n  /g' | sed 's/{/{\n  /g' | sed 's/}/\n}/g'
            echo ""
        fi
    else
        log "INFO" "IPv4 not available or test failed"
    fi
    
    # Try IPv6 (bypass VPN if active)
    log "INFO" "Testing IPv6 connectivity..."
    response_v6=$(sudo -g nonevpn curl -6 -sSL --max-time 30 "$test_url" 2>/dev/null || curl -6 -sSL --max-time 30 "$test_url" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$response_v6" | grep -q '"client_ip"'; then
        # Check for rate limit
        if echo "$response_v6" | grep -q '"error".*"rate_limit'; then
            log "ERROR" "Rate limit exceeded on reflector service"
            echo ""
            printf "  ${RED}Too many requests to the reflector service.${NC}\n"
            echo "  Please wait a few minutes before trying again."
            echo ""
            return 1
        fi
        
        has_ipv6=1
        client_ip_v6=$(get_client_ip "$response_v6")
        log "SUCCESS" "IPv6 test successful"
    else
        log "INFO" "IPv6 not available or test failed"
    fi
    
    # Check if at least one worked
    if [ $has_ipv4 -eq 0 ] && [ $has_ipv6 -eq 0 ]; then
        log "ERROR" "Failed to reach reflector service via IPv4 or IPv6"
        echo ""
        printf "  ${RED}Could not connect to the reflector service.${NC}\n"
        echo "  Please check your internet connection."
        echo ""
        return 1
    fi
    
    # Display results
    echo ""
    printf "${BLUE}=== Test Results ===${NC}\n"
    
    # Show IP addresses
    if [ $has_ipv4 -eq 1 ]; then
        printf "Public IPv4: ${YELLOW}%s${NC}\n" "$client_ip_v4"
    fi
    if [ $has_ipv6 -eq 1 ]; then
        printf "Public IPv6: ${YELLOW}%s${NC}\n" "$client_ip_v6"
    fi
    echo ""
    
    # Parse and display results for each port (POSIX-compatible)
    local all_reachable_v4=1
    local all_reachable_v6=1
    
    # Display IPv4 results
    if [ $has_ipv4 -eq 1 ]; then
        printf "${BLUE}IPv4:${NC}\n"
        for port in $(echo "$ports" | tr ',' ' '); do
            local reachable
            reachable=$(parse_json_result "$response_v4" "$port")
            
            if [ "$reachable" = "true" ]; then
                local latency
                latency=$(get_latency "$response_v4" "$port")
                printf "  Port %s: ${GREEN}✓${NC}" "$port"
                [ -n "$latency" ] && printf " %sms" "$latency"
                
                # Show compact SSH info if available (SSH takes priority over TLS)
                if has_ssh_info "$response_v4" "$port"; then
                    local ssh_banner ssh_protocol ssh_software
                    ssh_banner=$(get_ssh_banner "$response_v4" "$port")
                    ssh_protocol=$(get_ssh_protocol "$response_v4" "$port")
                    ssh_software=$(get_ssh_software "$response_v4" "$port")
                    
                    if [ -n "$ssh_software" ]; then
                        printf " | ${BLUE}SSH${NC} %s" "$ssh_software"
                    elif [ -n "$ssh_banner" ]; then
                        printf " | ${BLUE}SSH${NC} %s" "$ssh_banner"
                    fi
                    
                    # Check for SSH warnings
                    if [ "$ssh_protocol" = "1.0" ] || [ "$ssh_protocol" = "1" ]; then
                        printf " ${RED}(SSH-1)${NC}"
                    fi
                # Show compact TLS info if available (only if not SSH)
                elif has_tls_info "$response_v4" "$port"; then
                    local tls_version cert_subject days_until_expiry
                    tls_version=$(get_tls_version "$response_v4" "$port")
                    cert_subject=$(get_cert_subject "$response_v4" "$port")
                    days_until_expiry=$(get_cert_days_until_expiry "$response_v4" "$port")
                    
                    printf " | ${BLUE}%s${NC}" "$tls_version"
                    
                    if [ -n "$cert_subject" ]; then
                        printf " | %s" "$cert_subject"
                        is_cert_self_signed "$response_v4" "$port" && printf " ${YELLOW}(self-signed)${NC}"
                    fi
                    
                    if [ -n "$days_until_expiry" ]; then
                        if [ "$days_until_expiry" -lt 30 ]; then
                            printf " | ${RED}exp: %dd${NC}" "$days_until_expiry"
                        elif [ "$days_until_expiry" -lt 90 ]; then
                            printf " | ${YELLOW}exp: %dd${NC}" "$days_until_expiry"
                        fi
                    fi
                fi
                printf "\n"
            else
                printf "  Port %s: ${RED}✗${NC}\n" "$port"
                all_reachable_v4=0
            fi
        done
    fi
    
    # Display IPv6 results
    if [ $has_ipv6 -eq 1 ]; then
        printf "${BLUE}IPv6:${NC}\n"
        for port in $(echo "$ports" | tr ',' ' '); do
            local reachable
            reachable=$(parse_json_result "$response_v6" "$port")
            
            if [ "$reachable" = "true" ]; then
                local latency
                latency=$(get_latency "$response_v6" "$port")
                printf "  Port %s: ${GREEN}✓${NC}" "$port"
                [ -n "$latency" ] && printf " %sms" "$latency"
                
                # Show compact SSH info if available (SSH takes priority over TLS)
                if has_ssh_info "$response_v6" "$port"; then
                    local ssh_banner ssh_protocol ssh_software
                    ssh_banner=$(get_ssh_banner "$response_v6" "$port")
                    ssh_protocol=$(get_ssh_protocol "$response_v6" "$port")
                    ssh_software=$(get_ssh_software "$response_v6" "$port")
                    
                    if [ -n "$ssh_software" ]; then
                        printf " | ${BLUE}SSH${NC} %s" "$ssh_software"
                    elif [ -n "$ssh_banner" ]; then
                        printf " | ${BLUE}SSH${NC} %s" "$ssh_banner"
                    fi
                    
                    # Check for SSH warnings
                    if [ "$ssh_protocol" = "1.0" ] || [ "$ssh_protocol" = "1" ]; then
                        printf " ${RED}(SSH-1)${NC}"
                    fi
                # Show compact TLS info if available (only if not SSH)
                elif has_tls_info "$response_v6" "$port"; then
                    local tls_version cert_subject days_until_expiry
                    tls_version=$(get_tls_version "$response_v6" "$port")
                    cert_subject=$(get_cert_subject "$response_v6" "$port")
                    days_until_expiry=$(get_cert_days_until_expiry "$response_v6" "$port")
                    
                    printf " | ${BLUE}%s${NC}" "$tls_version"
                    
                    if [ -n "$cert_subject" ]; then
                        printf " | %s" "$cert_subject"
                        is_cert_self_signed "$response_v6" "$port" && printf " ${YELLOW}(self-signed)${NC}"
                    fi
                    
                    if [ -n "$days_until_expiry" ]; then
                        if [ "$days_until_expiry" -lt 30 ]; then
                            printf " | ${RED}exp: %dd${NC}" "$days_until_expiry"
                        elif [ "$days_until_expiry" -lt 90 ]; then
                            printf " | ${YELLOW}exp: %dd${NC}" "$days_until_expiry"
                        fi
                    fi
                fi
                printf "\n"
            else
                printf "  Port %s: ${RED}✗${NC}\n" "$port"
                all_reachable_v6=0
            fi
        done
    fi
    
    echo ""
    
    # Store results for final summary (using global variables for simplicity)
    TEST_HAS_IPV4=$has_ipv4
    TEST_HAS_IPV6=$has_ipv6
    TEST_ALL_REACHABLE_V4=$all_reachable_v4
    TEST_ALL_REACHABLE_V6=$all_reachable_v6
    
    return 0
}

# Wait for user input or timeout
wait_for_user() {
    local timeout="$1"
    
    log "INFO" "Firewall is now open for testing"
    echo ""
    printf "Test your router at: ${GREEN}https://reflector.example.com${NC}\n"
    printf "Press ${YELLOW}ENTER${NC} when done or wait ${YELLOW}%s seconds${NC} for timeout\n" "$timeout"
    echo ""
    
    # Check if we have a TTY available (not running via pipe like curl | sh)
    if [ -t 0 ]; then
        # Read from stdin with timeout (normal interactive mode)
        if read -t "$timeout" -r; then
            log "INFO" "User pressed ENTER"
            return 0
        else
            log "WARNING" "Timeout reached (${timeout} seconds)"
            return 1
        fi
    elif [ -r /dev/tty ]; then
        # Read from TTY directly (piped execution like curl | sh)
        if read -t "$timeout" -r < /dev/tty; then
            log "INFO" "User pressed ENTER"
            return 0
        else
            log "WARNING" "Timeout reached (${timeout} seconds)"
            return 1
        fi
    else
        # No TTY available at all - just sleep and timeout
        log "WARNING" "No terminal available, waiting ${timeout} seconds..."
        sleep "$timeout"
        log "WARNING" "Timeout reached (${timeout} seconds)"
        return 1
    fi
}

# Cleanup function (called on exit)
cleanup() {
    local exit_code=$?
    log "INFO" "Cleaning up..."
    
    if [ "$FIREWALL_WAS_OPEN" -eq 0 ]; then
        # Firewall was closed before, close it again
        close_firewall
    else
        log "INFO" "Firewall was already open before test, keeping it open"
    fi
    echo ""
    echo "If this script was helpful, please consider supporting the project:"
    echo "  - GitHub: github.com/sponsors/admonstrator"
    echo "  - Ko-fi: ko-fi.com/admon"
    echo "  - Buy Me a Coffee: buymeacoffee.com/admon"
    echo ""
    exit $exit_code
}

# Main function
main() {
    printf "\n${BLUE}GL.iNet Router Firewall Test${NC} v%s\n\n" "$SCRIPT_VERSION"
    
    # Check if running as root
    check_root
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --ports)
                PORTS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --auto-test|-t)
                AUTO_TEST=1
                shift
                ;;
            --debug|-d)
                DEBUG=1
                shift
                ;;
            --cleanup)
                check_root
                remove_firewall_rule
                exit 0
                ;;
            --help|-h)
                echo "Usage: $SCRIPT_NAME [OPTIONS]"
                echo ""
                echo "Only the following ports are supported:"
                echo "TCP ports: 22,80,443,8080,8443"
                echo "All other ports are blocked by the reflector service."
                echo ""
                echo "Options:"
                echo "  --ports <ports>        Comma-separated list of ports (default: 80,443)"
                echo "  --timeout <seconds>    Timeout in seconds (default: 300)"
                echo "  --auto-test, -t        Run automatic test (no manual intervention)"
                echo "  --debug, -d            Show raw JSON responses (debug mode)"
                echo "  --cleanup              Remove firewall rule and exit"
                echo "  --help, -h             Show this help message"
                echo ""
                echo "Examples:"
                echo "  $SCRIPT_NAME                           # Interactive mode"
                echo "  $SCRIPT_NAME --auto-test               # Automatic test mode"
                echo "  $SCRIPT_NAME --ports 8080,8443 -t     # Test custom ports"
                echo "  $SCRIPT_NAME --cleanup                 # Remove firewall rule"
                echo ""
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Check current firewall state for both IPv4 and IPv6
    FIREWALL_WAS_OPEN_IPV4=0
    FIREWALL_WAS_OPEN_IPV6=0
    
    get_firewall_rule_state "ipv4"
    FIREWALL_STATE_IPV4=$?
    
    get_firewall_rule_state "ipv6"
    FIREWALL_STATE_IPV6=$?
    
    case $FIREWALL_STATE_IPV4 in
        0)
            log "WARNING" "IPv4 firewall rule already exists and is ENABLED"
            FIREWALL_WAS_OPEN_IPV4=1
            ;;
        1)
            log "INFO" "IPv4 firewall rule exists but is DISABLED"
            FIREWALL_WAS_OPEN_IPV4=0
            ;;
        2)
            log "INFO" "IPv4 firewall rule does not exist (firewall is CLOSED)"
            FIREWALL_WAS_OPEN_IPV4=0
            ;;
    esac
    
    case $FIREWALL_STATE_IPV6 in
        0)
            log "WARNING" "IPv6 firewall rule already exists and is ENABLED"
            FIREWALL_WAS_OPEN_IPV6=1
            ;;
        1)
            log "INFO" "IPv6 firewall rule exists but is DISABLED"
            FIREWALL_WAS_OPEN_IPV6=0
            ;;
        2)
            log "INFO" "IPv6 firewall rule does not exist (firewall is CLOSED)"
            FIREWALL_WAS_OPEN_IPV6=0
            ;;
    esac
    
    # Set FIREWALL_WAS_OPEN to 1 if either was open
    FIREWALL_WAS_OPEN=0
    if [ $FIREWALL_WAS_OPEN_IPV4 -eq 1 ] || [ $FIREWALL_WAS_OPEN_IPV6 -eq 1 ]; then
        FIREWALL_WAS_OPEN=1
    fi
    
    # Set trap for cleanup
    trap cleanup EXIT INT TERM
    
    # Open firewall
    if ! open_firewall "$PORTS"; then
        log "ERROR" "Failed to open firewall"
        exit 1
    fi
    
    # Run automatic test or wait for user
    if [ "$AUTO_TEST" -eq 1 ]; then
        run_auto_test "$PORTS"
    else
        wait_for_user "$TIMEOUT"
    fi
    
    # Cleanup will be called automatically via trap
    
    # Final summary
    echo ""
    if [ "$AUTO_TEST" -eq 1 ]; then
        local any_reachable=0
        if [ "${TEST_HAS_IPV4:-0}" -eq 1 ] && [ "${TEST_ALL_REACHABLE_V4:-0}" -eq 1 ]; then
            any_reachable=1
        fi
        if [ "${TEST_HAS_IPV6:-0}" -eq 1 ] && [ "${TEST_ALL_REACHABLE_V6:-0}" -eq 1 ]; then
            any_reachable=1
        fi
        
        if [ $any_reachable -eq 1 ]; then
            printf "${GREEN}✓ Router is reachable from the internet!${NC}\n"
            echo "You should be able to host services / VPN from your router."
        else
            printf "${YELLOW}⚠ Some ports are not reachable${NC}\n"
            echo "Possible reasons: CGNAT, port forwarding not configured, ISP blocks ports"
            echo "You might NOT be able to host services / VPN from your router."
        fi
    else
        log "SUCCESS" "Test completed"
    fi
}

# Run main function
main "$@"