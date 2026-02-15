#!/bin/bash
# smart_dfir_hunt_v3.sh
# Smart DFIR Network Scanner + Persistence Hunting + Hidden Socket Finder (v3)
#
# Adds (requested 1–8 + profile toggle):
# 1) eBPF rootkit / BPFdoor-style checks (bpffs, pinned objs, bpftool, XDP/TC)
# 2) systemd Generators persistence checks
# 3) udev rules persistence checks
# 4) PAM/NSS/credential-intercept checks + security module dirs
# 5) Network namespace tricks (lsns/ip netns/proc ns)
# 6) “Magic packet” / port-knocking style hints (conntrack, optional tcpdump sample disabled)
# 7) Stronger hidden socket detection (ss vs proc + netstat/lsof views + inode->pid mapping)
# 8) Container / cloud persistence hooks (docker/crictl)
# + Profile toggle: PROFILE=endpoint|lab (default endpoint)
# + Risk scoring + baseline learn mode + dpkg integrity (debsums if installed; dpkg --verify fallback)
#
# Run:
#   sudo PROFILE=endpoint bash smart_dfir_hunt_v3.sh
#   sudo PROFILE=lab bash smart_dfir_hunt_v3.sh
# Optional:
#   sudo LEARN_BASELINE=1 BASELINE_FILE=baseline_exec_allowlist.txt bash smart_dfir_hunt_v3.sh
#   sudo BASELINE_ALLOWLIST_FILE=/path/to/allowlist_regex.txt bash smart_dfir_hunt_v3.sh
#
set -u
umask 077

########################################
# UI helpers
########################################
supports_color() { [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; }
if supports_color; then
  C_RESET="$(tput sgr0)"; C_BOLD="$(tput bold)"; C_DIM="$(tput dim)"
  C_RED="$(tput setaf 1)"; C_YELLOW="$(tput setaf 3)"; C_GREEN="$(tput setaf 2)"; C_BLUE="$(tput setaf 4)"
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_YELLOW=""; C_GREEN=""; C_BLUE=""
fi
banner() { echo "${C_BOLD}${C_BLUE}==> $*${C_RESET}"; }
info()   { echo "${C_BLUE}[i]${C_RESET} $*"; }
ok()     { echo "${C_GREEN}[OK]${C_RESET} $*"; }
warn()   { echo "${C_YELLOW}[WARN]${C_RESET} $*"; }
sus()    { echo "${C_RED}[SUSPICIOUS]${C_RESET} $*"; }
have()   { command -v "$1" >/dev/null 2>&1; }

########################################
# Profile toggle
########################################
PROFILE="${PROFILE:-endpoint}"   # endpoint|lab
if [[ "$PROFILE" != "endpoint" && "$PROFILE" != "lab" ]]; then
  echo "[!] Invalid PROFILE=$PROFILE (use endpoint|lab)" >&2
  exit 2
fi

########################################
# Risk scoring
########################################
RISK_SCORE=0
declare -a FINDINGS=()  # accumulate short findings for Top-10

add_risk() {
  local pts="$1"; shift
  local msg="${*:-}"
  RISK_SCORE=$((RISK_SCORE + pts))
  [ -n "$msg" ] && FINDINGS+=("[$pts] $msg")
}

# Profile-based weights (tuned for signal vs noise)
# (lab expects more BPF/netns/container noise)
W_TEMP_EXE=40
W_DELETED_EXE=40
W_UNUSUAL_PATH=10
W_NO_DPKG_OWNER=15
W_PUBLIC_LISTENER=10
W_FORWARDING=10
W_ICMP_REDIRECTS=5
W_RPFILTER_LOOSE=3
W_SOURCE_ROUTE=15
W_SUSPICIOUS_SYSTEMD=25
W_SUSPICIOUS_CRON=40
W_LD_SO_PRELOAD=70
W_SUID_WEIRD=60
W_HIDDEN_SOCKET=55
W_INODE_NO_PID=20
W_DPKG_BIN_MISMATCH=55
W_DPKG_OTHER_MISMATCH=10
W_EBPF_PRESENT=15
W_EBPF_SUSPICIOUS=40
W_NETNS_UNEXPECTED=10
W_UDEV_SUSPICIOUS=35
W_PAM_SUSPICIOUS=35
W_CONTAINER_SUSPICIOUS=15

if [ "$PROFILE" = "lab" ]; then
  W_EBPF_PRESENT=5
  W_EBPF_SUSPICIOUS=20
  W_NETNS_UNEXPECTED=5
  W_CONTAINER_SUSPICIOUS=5
  W_PUBLIC_LISTENER=7
  W_UNUSUAL_PATH=7
fi

########################################
# Config / Baseline
########################################
timestamp="$(date +"%Y-%m-%d_%H-%M-%S")"
output_dir="forensic_hunt_${timestamp}"
mkdir -p "$output_dir"

BASELINE_FILE="${BASELINE_FILE:-baseline_exec_allowlist.txt}"
LEARN_BASELINE="${LEARN_BASELINE:-0}"
BASELINE_ALLOWLIST_FILE="${BASELINE_ALLOWLIST_FILE:-}"

allowlist_loaded=0
declare -a ALLOWLIST_REGEX=()
if [ -n "${BASELINE_ALLOWLIST_FILE}" ] && [ -f "${BASELINE_ALLOWLIST_FILE}" ]; then
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$line" ] && continue
    ALLOWLIST_REGEX+=("$line")
  done < "${BASELINE_ALLOWLIST_FILE}"
  allowlist_loaded=1
fi

is_allowlisted() {
  local s="$1"
  [ "$allowlist_loaded" -eq 1 ] || return 1
  local r
  for r in "${ALLOWLIST_REGEX[@]}"; do
    echo "$s" | grep -Eq "$r" && return 0
  done
  return 1
}

########################################
# Helpers
########################################
run_cmd() {
  local outfile="$1"; shift
  info "Collecting: $outfile"
  {
    echo "### COMMAND: $*"
    echo "### DATE: $(date -Is)"
    echo
    "$@"
  } > "${output_dir}/${outfile}" 2>&1 || true
}

sysctl_read() { sysctl -n "$1" 2>/dev/null || echo "NA"; }

path_trust_class() {
  local exe="$1"
  [ -z "$exe" ] && { echo "SUSPICIOUS"; return; }
  case "$exe" in /tmp/*|/var/tmp/*|/dev/shm/*) echo "SUSPICIOUS"; return ;; esac
  case "$exe" in
    /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*|/lib/*|/lib64/*|/usr/libexec/*|/libexec/*) echo "TRUSTED"; return ;;
    /snap/*) echo "LIKELY_OK"; return ;;
    /opt/*|/home/*) echo "UNUSUAL"; return ;;
  esac
  echo "UNUSUAL"
}

dpkg_owner() {
  local exe="$1"
  [ -z "$exe" ] && return
  have dpkg-query && dpkg-query -S "$exe" 2>/dev/null | head -n 1 || true
}
pkg_from_dpkg_owner_line() { echo "$1" | awk -F':' '{print $1 ":" $2}' 2>/dev/null || true; }

integrity_check_pkg() {
  local pkg="$1"
  [ -z "$pkg" ] && return
  if have debsums; then
    local out
    out="$(debsums -s -a "$pkg" 2>/dev/null || true)"
    if [ -n "$out" ]; then
      echo "FAIL(debsums): $pkg"; echo "$out"
    else
      echo "OK(debsums): $pkg"
    fi
    return
  fi
  if have dpkg; then
    local vout
    vout="$(dpkg --verify "$pkg" 2>/dev/null || true)"
    if [ -n "$vout" ]; then
      echo "FAIL(dpkg --verify): $pkg"; echo "$vout"
    else
      echo "OK(dpkg --verify): $pkg"
    fi
    return
  fi
  echo "NA: no integrity tool available for $pkg"
}

classify_integrity_line() {
  local line="$1"
  # config (usually benign)
  if echo "$line" | grep -q ' c '; then echo "INFO"; return; fi
  # checksum change + binary/lib path => suspicious
  if echo "$line" | grep -Eq '^[^?]*5' && echo "$line" | grep -Eq '/(bin|sbin|lib|lib64)/'; then
    echo "SUSPICIOUS"; return
  fi
  echo "WARN"
}

########################################
# Start
########################################
banner "Smart DFIR Hunt v3 (PROFILE=$PROFILE)"
info "Output directory: ${C_BOLD}$output_dir${C_RESET}"
info "User: $(id -un) uid=$(id -u)"
if [ "$(id -u)" -ne 0 ]; then
  warn "Not root: some checks (inode->PID mapping, firewall, full persistence reads) will be incomplete."
fi
if [ "$allowlist_loaded" -eq 1 ]; then ok "Loaded allowlist regex: $BASELINE_ALLOWLIST_FILE"; else info "No allowlist regex loaded."; fi

########################################
# Core evidence collection
########################################
banner "1) Core host + network evidence"
run_cmd "system_info.txt" bash -lc 'uname -a; echo; hostnamectl; echo; uptime; echo; date -Is'
run_cmd "os_release.txt"  bash -lc 'cat /etc/os-release 2>/dev/null || true'
run_cmd "ip_addr.txt" ip addr show
run_cmd "ip_link.txt" ip link show
run_cmd "ip_link_stats.txt" ip -s link
run_cmd "routing_table_main.txt" ip route show
run_cmd "routing_table_all.txt"  ip route show table all
run_cmd "ip_rule.txt" ip rule show
run_cmd "ip_neigh.txt" ip neigh show

run_cmd "dns_resolv_conf.txt" bash -lc 'ls -l /etc/resolv.conf; echo; cat /etc/resolv.conf'
have resolvectl && run_cmd "resolvectl_status.txt" resolvectl status || echo "resolvectl not found" > "${output_dir}/resolvectl_status.txt"
have nmcli && run_cmd "nmcli_dev_show.txt" nmcli dev show || echo "nmcli not found" > "${output_dir}/nmcli_dev_show.txt"
run_cmd "proxy_env.txt" bash -lc 'env | grep -iE "^(http|https|ftp|all|no)_proxy=" || true'

run_cmd "ss_tulnp.txt" ss -tulnp
run_cmd "ss_tunap.txt" ss -tunap
run_cmd "ss_established_tcp.txt" bash -lc 'ss -Htanp state established || true'
run_cmd "ss_socket_summary.txt" ss -s
have lsof && run_cmd "lsof_i.txt" lsof -nP -i || echo "lsof not found" > "${output_dir}/lsof_i.txt"
have netstat && run_cmd "netstat_plant.txt" netstat -plant || echo "netstat not found" > "${output_dir}/netstat_plant.txt"

banner "2) Firewall evidence"
have ufw && run_cmd "ufw_status_verbose.txt" ufw status verbose || echo "ufw not found" > "${output_dir}/ufw_status_verbose.txt"
have nft && run_cmd "nft_ruleset.txt" bash -lc 'nft list ruleset || true' || echo "nft not found" > "${output_dir}/nft_ruleset.txt"
have iptables-save && run_cmd "iptables_save.txt" bash -lc 'iptables-save || true' || echo "iptables-save not found" > "${output_dir}/iptables_save.txt"

banner "3) Process inventory"
run_cmd "process_tree.txt" bash -lc 'ps -eo pid,ppid,user,stat,lstart,cmd --forest'

########################################
# Live triage: sysctl + public listeners + promisc
########################################
banner "LIVE TRIAGE: Network attack surface"

ip_fwd="$(sysctl_read net.ipv4.ip_forward)"
v6_fwd="$(sysctl_read net.ipv6.conf.all.forwarding)"
acc_redir="$(sysctl_read net.ipv4.conf.all.accept_redirects)"
snd_redir="$(sysctl_read net.ipv4.conf.all.send_redirects)"
rp_filter="$(sysctl_read net.ipv4.conf.all.rp_filter)"
src_route="$(sysctl_read net.ipv4.conf.all.accept_source_route)"

if [ "$ip_fwd" = "1" ] || [ "$v6_fwd" = "1" ]; then
  warn "Forwarding enabled (v4=$ip_fwd v6=$v6_fwd)"; add_risk "$W_FORWARDING" "IP forwarding enabled"
else ok "Forwarding disabled (v4=$ip_fwd v6=$v6_fwd)"; fi

if [ "$acc_redir" = "1" ] || [ "$snd_redir" = "1" ]; then
  warn "ICMP redirects enabled (accept=$acc_redir send=$snd_redir)"; add_risk "$W_ICMP_REDIRECTS" "ICMP redirects enabled"
else ok "ICMP redirects disabled"; fi

if [ "$rp_filter" = "0" ]; then
  warn "rp_filter=0 (loose)"; add_risk "$W_RPFILTER_LOOSE" "rp_filter loose/disabled"
else ok "rp_filter=$rp_filter"; fi

if [ "$src_route" = "1" ]; then
  sus "accept_source_route=1"; add_risk "$W_SOURCE_ROUTE" "accept_source_route enabled"
else ok "accept_source_route=$src_route"; fi

public_listeners="$(ss -Hltunp 2>/dev/null | awk '$4 ~ /^0\.0\.0\.0:|^\[::\]:|^:::/ {print}')"
if [ -n "${public_listeners}" ]; then
  warn "Public listeners detected (0.0.0.0/::):"; echo "$public_listeners" | sed 's/^/  /'
  add_risk "$W_PUBLIC_LISTENER" "Public listeners bound to all interfaces"
else ok "No listeners bound to all interfaces"; fi

run_cmd "promiscuous_mode.txt" bash -lc 'ip link | grep -E "PROMISC" || true'
if ip link 2>/dev/null | grep -q "PROMISC"; then
  sus "PROMISC interface detected"; add_risk 20 "Interface in promiscuous mode"
else ok "No PROMISC interfaces"; fi

########################################
# Network PID attribution + temp execution
########################################
banner "LIVE TRIAGE: Network PID attribution"
pids="$(ss -tunap 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u || true)"

{
  echo "PID|PPID|USER|EXE|CWD|TRUST|DPKG_OWNER|CMDLINE"
  for pid in $pids; do
    [ -d "/proc/$pid" ] || continue
    ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo "")"
    user="$(ps -o user= -p "$pid" 2>/dev/null | awk '{print $1}')"
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo "")"
    cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    trust="$(path_trust_class "$exe")"
    owner="$(dpkg_owner "$exe")"
    echo "${pid}|${ppid}|${user}|${exe}|${cwd}|${trust}|${owner}|${cmd}"
  done
} > "${output_dir}/network_pid_intel.txt" 2>/dev/null || true

if [ "$LEARN_BASELINE" = "1" ] && [ -s "${output_dir}/network_pid_intel.txt" ]; then
  info "Learning baseline executable paths -> $BASELINE_FILE"
  awk -F'|' 'NR>1 && $4!="" {print $4}' "${output_dir}/network_pid_intel.txt" | sort -u > "$BASELINE_FILE"
  ok "Baseline created: $BASELINE_FILE"
fi

if [ -s "${output_dir}/network_pid_intel.txt" ]; then
  while IFS='|' read -r pid ppid user exe cwd trust owner cmd; do
    [ "$pid" = "PID" ] && continue

    if [ -f "$BASELINE_FILE" ] && grep -qx "$exe" "$BASELINE_FILE"; then
      ok "Baseline EXE: PID=$pid USER=$user EXE=$exe"
      continue
    fi
    if is_allowlisted "$exe" || is_allowlisted "$cmd"; then
      ok "ALLOWLISTED: PID=$pid USER=$user EXE=$exe"
      continue
    fi

    case "$trust" in
      TRUSTED)
        if [ -n "$owner" ] || [[ "$exe" == /snap/* ]]; then
          ok "PID=$pid USER=$user EXE=$exe"
        else
          warn "PID=$pid USER=$user EXE=$exe (no dpkg owner)"
          add_risk "$W_NO_DPKG_OWNER" "Network process binary has no dpkg owner: $exe"
        fi
        ;;
      LIKELY_OK)
        ok "PID=$pid USER=$user EXE=$exe (snap)"
        ;;
      UNUSUAL)
        warn "PID=$pid USER=$user EXE=$exe (unusual path) CWD=$cwd"
        add_risk "$W_UNUSUAL_PATH" "Network process in unusual path: $exe"
        if [ -z "$owner" ]; then
          warn "  ↳ No dpkg owner: review cmdline"
          add_risk "$W_NO_DPKG_OWNER" "Unusual-path network process has no dpkg owner: $exe"
        fi
        ;;
      SUSPICIOUS)
        sus "PID=$pid USER=$user EXE=$exe (temp/shm path) CWD=$cwd"
        add_risk "$W_TEMP_EXE" "Process executing from temp/shm: $exe"
        ;;
    esac
  done < "${output_dir}/network_pid_intel.txt"
else
  warn "No network PID intel captured."
fi

banner "LIVE TRIAGE: Temp execution / deleted executables"
tmp_regex='^(/tmp/|/var/tmp/|/dev/shm/)'
{
  echo "PID|USER|EXE|CWD|NOTE"
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    [ -d "/proc/$pid" ] || continue
    user="$(ps -o user= -p "$pid" 2>/dev/null | awk '{print $1}')"
    exe_link="$(ls -l "/proc/$pid/exe" 2>/dev/null || true)"
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo "")"

    note=""
    [[ "$exe" =~ $tmp_regex ]] && note+="EXE_IN_TEMP;"
    [[ "$cwd" =~ $tmp_regex ]] && note+="CWD_IN_TEMP;"
    echo "$exe_link" | grep -q "(deleted)" && note+="EXE_DELETED;"

    [ -n "$note" ] && echo "${pid}|${user}|${exe}|${cwd}|${note}"
  done
} > "${output_dir}/temp_execution_findings.txt" 2>/dev/null || true

if [ -s "${output_dir}/temp_execution_findings.txt" ] && [ "$(wc -l < "${output_dir}/temp_execution_findings.txt")" -gt 1 ]; then
  sus "Temp/deleted-exe findings:"; tail -n +2 "${output_dir}/temp_execution_findings.txt" | sed 's/^/  /'
  add_risk "$W_TEMP_EXE" "Temp/deleted-executable indicators present"
  if grep -q "EXE_DELETED" "${output_dir}/temp_execution_findings.txt"; then
    add_risk "$W_DELETED_EXE" "Deleted executable still running"
  fi
else ok "No temp execution / deleted exes"; fi

########################################
# dpkg integrity for network-facing packages (severity-aware)
########################################
banner "LIVE TRIAGE: Package integrity (network-facing packages)"
pkgs_file="${output_dir}/network_pkgs.txt"; : > "$pkgs_file"
integrity_report="${output_dir}/dpkg_integrity_report.txt"; : > "$integrity_report"

if [ -s "${output_dir}/network_pid_intel.txt" ]; then
  awk -F'|' 'NR>1 && $7!="" {print $7}' "${output_dir}/network_pid_intel.txt" \
    | while IFS= read -r ownerline; do
        pkg="$(pkg_from_dpkg_owner_line "$ownerline")"
        [ -n "$pkg" ] && echo "$pkg"
      done | sort -u > "$pkgs_file"
fi

if [ -s "$pkgs_file" ]; then
  if have debsums; then ok "Using debsums"; else warn "debsums not installed -> dpkg --verify fallback"; fi
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    info "Integrity checking: $pkg"
    result="$(integrity_check_pkg "$pkg")"
    echo "==== $pkg ====" >> "$integrity_report"
    echo "$result" >> "$integrity_report"; echo >> "$integrity_report"

    if echo "$result" | grep -q '^FAIL'; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        sev="$(classify_integrity_line "$line")"
        case "$sev" in
          SUSPICIOUS)
            sus "Binary/library integrity mismatch: $pkg -> $line"
            add_risk "$W_DPKG_BIN_MISMATCH" "Binary/lib integrity mismatch in $pkg"
            ;;
          WARN)
            warn "Integrity drift: $pkg -> $line"
            add_risk "$W_DPKG_OTHER_MISMATCH" "Integrity drift in $pkg"
            ;;
          INFO)
            info "Config modified: $pkg -> $line"
            ;;
        esac
      done <<< "$(echo "$result" | tail -n +2)"
    else
      ok "Integrity OK: $pkg"
    fi
  done < "$pkgs_file"
else
  info "No dpkg-owned network packages to verify (snaps/custom binaries may be normal)."
fi

################################################################################
# PERSISTENCE HUNTING MODE (classic + modern additions)
################################################################################
banner "PERSISTENCE HUNTING: systemd, cron, ssh, sudoers, polkit, preload, suid/sgid"

# systemd services/timers + suspicious ExecStart (enabled)
if have systemctl; then
  run_cmd "systemd_enabled_services.txt" systemctl list-unit-files --type=service --state=enabled
  run_cmd "systemd_enabled_timers.txt" systemctl list-unit-files --type=timer --state=enabled
  run_cmd "systemd_running_services.txt" systemctl list-units --type=service --state=running
  run_cmd "systemd_running_timers.txt" systemctl list-units --type=timer --state=running

  enabled_services="$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | awk 'NR>1 && $1 ~ /\.service$/ {print $1}')"
  exec_report="${output_dir}/systemd_execstart_review.txt"; : > "$exec_report"

  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    execstart="$(systemctl show "$svc" -p ExecStart 2>/dev/null | sed 's/^ExecStart=//')"
    [ -z "$execstart" ] && continue
    echo "[$svc] $execstart" >> "$exec_report"
    first_path="$(echo "$execstart" | grep -oE '/[^ ;,]+' | head -n 1 || true)"
    trust="$(path_trust_class "$first_path")"

    if is_allowlisted "$svc" || is_allowlisted "$first_path"; then
      ok "ALLOWLISTED systemd unit: $svc"; continue
    fi

    case "$trust" in
      TRUSTED|LIKELY_OK) : ;;
      UNUSUAL)
        warn "Enabled systemd service with unusual ExecStart: $svc -> $first_path"
        add_risk "$W_SUSPICIOUS_SYSTEMD" "Enabled systemd service with unusual ExecStart: $svc"
        ;;
      SUSPICIOUS)
        sus "Enabled systemd service executing from temp: $svc -> $first_path"
        add_risk 70 "Enabled systemd service executing from temp: $svc"
        ;;
    esac
  done <<< "$enabled_services"
else
  warn "systemctl not available."
fi

# Cron and at
run_cmd "cron_system_dirs.txt" bash -lc 'ls -la /etc/cron* 2>/dev/null || true'
run_cmd "crontab_system.txt" bash -lc 'cat /etc/crontab 2>/dev/null || true'
run_cmd "cron_spool.txt" bash -lc 'ls -la /var/spool/cron/crontabs 2>/dev/null || true'
run_cmd "cron_user_list.txt" bash -lc 'cut -d: -f1 /etc/passwd | while read -r u; do crontab -l -u "$u" 2>/dev/null && echo "----"; done || true'
have atq && run_cmd "atq.txt" atq || echo "atq not found" > "${output_dir}/atq.txt"

cron_grep_out="${output_dir}/cron_suspicious_grep.txt"
grep -RniE --binary-files=without-match '(curl|wget|nc |ncat|socat|bash -i|python -c|perl -e|/dev/tcp|base64|openssl enc|mkfifo|authorized_keys)' \
  /etc/cron* /var/spool/cron/crontabs /etc/crontab 2>/dev/null > "$cron_grep_out" || true
if [ -s "$cron_grep_out" ]; then
  sus "Suspicious patterns found in cron (review cron_suspicious_grep.txt)"
  head -n 20 "$cron_grep_out" | sed 's/^/  /'
  add_risk "$W_SUSPICIOUS_CRON" "Suspicious cron patterns detected"
else ok "No obvious suspicious cron keywords"; fi

# SSH backdoor posture + authorized_keys
run_cmd "sshd_config_or_effective.txt" bash -lc 'sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null || true'
run_cmd "authorized_keys_root.txt" bash -lc 'ls -la /root/.ssh 2>/dev/null; cat /root/.ssh/authorized_keys 2>/dev/null || true'
auth_keys_report="${output_dir}/authorized_keys_all_users.txt"; : > "$auth_keys_report"
while IFS=: read -r user _ uid _ _ home shell; do
  [ -z "$home" ] && continue
  [ -d "$home/.ssh" ] || continue
  {
    echo "== $user (uid=$uid) home=$home shell=$shell =="
    ls -la "$home/.ssh" 2>/dev/null || true
    [ -f "$home/.ssh/authorized_keys" ] && cat "$home/.ssh/authorized_keys" || echo "(no authorized_keys)"
    echo
  } >> "$auth_keys_report"
done < /etc/passwd

# sudoers + polkit
run_cmd "sudoers.txt" bash -lc 'ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null; cat /etc/sudoers 2>/dev/null || true; grep -Rni . /etc/sudoers.d 2>/dev/null || true'
run_cmd "polkit_rules.txt" bash -lc 'ls -la /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d 2>/dev/null || true; grep -Rni . /etc/polkit-1/rules.d 2>/dev/null || true'

# ld.so.preload + LD_* env
run_cmd "ld_so_preload.txt" bash -lc 'ls -la /etc/ld.so.preload 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null || true'
if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
  sus "/etc/ld.so.preload is non-empty"; add_risk "$W_LD_SO_PRELOAD" "/etc/ld.so.preload non-empty"
fi
preload_grep="${output_dir}/ld_preload_env_grep.txt"
grep -RniE --binary-files=without-match '(LD_PRELOAD|LD_LIBRARY_PATH)' \
  /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc /etc/zsh/zshrc 2>/dev/null > "$preload_grep" || true
[ -s "$preload_grep" ] && { warn "LD_* environment references found (review)"; add_risk 10 "LD_* environment references found"; } || true

# XDG autostart + shell hooks
run_cmd "xdg_autostart_system.txt" bash -lc 'ls -la /etc/xdg/autostart 2>/dev/null || true; sed -n "1,200p" /etc/xdg/autostart/*.desktop 2>/dev/null || true'
run_cmd "xdg_autostart_user.txt" bash -lc 'find /home -maxdepth 3 -path "*/.config/autostart/*.desktop" -print -exec sed -n "1,120p" {} \; 2>/dev/null || true'
run_cmd "shell_profile_hooks.txt" bash -lc 'for f in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc; do echo "== $f =="; [ -f "$f" ] && sed -n "1,200p" "$f"; done'

# kernel modules + modules-load.d
run_cmd "lsmod.txt" bash -lc 'lsmod 2>/dev/null || true'
run_cmd "modules_load_conf.txt" bash -lc 'ls -la /etc/modules-load.d 2>/dev/null || true; grep -Rni . /etc/modules-load.d 2>/dev/null || true'

# SUID/SGID scan
run_cmd "suid_sgid_bins.txt" bash -lc 'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort'
suid_sus="${output_dir}/suid_sgid_suspicious_paths.txt"
grep -E '^(/tmp/|/var/tmp/|/dev/shm/|/home/|/opt/)' "${output_dir}/suid_sgid_bins.txt" > "$suid_sus" 2>/dev/null || true
if [ -s "$suid_sus" ]; then
  sus "SUID/SGID binaries in unusual paths"; head -n 20 "$suid_sus" | sed 's/^/  /'
  add_risk "$W_SUID_WEIRD" "SUID/SGID binaries in unusual locations"
else ok "No SUID/SGID binaries in obvious suspicious locations"; fi

################################################################################
# (1) eBPF checks
################################################################################
banner "1) eBPF / bpffs checks"
run_cmd "mounts_bpf.txt" bash -lc 'mount | grep -E "bpf|bpffs" || true'
run_cmd "sys_fs_bpf_listing.txt" bash -lc 'ls -la /sys/fs/bpf 2>/dev/null || true; find /sys/fs/bpf -maxdepth 4 -type f -o -type l 2>/dev/null || true'

if mount | grep -qiE 'bpffs| type bpf '; then
  warn "bpffs appears mounted"; add_risk "$W_EBPF_PRESENT" "bpffs mounted"
else
  ok "bpffs not detected (or not mounted)"
fi

if have bpftool; then
  run_cmd "bpftool_prog_show.txt" bpftool prog show
  run_cmd "bpftool_map_show.txt"  bpftool map show
  run_cmd "bpftool_link_show.txt" bpftool link show
  run_cmd "bpftool_net_show.txt"  bpftool net show

  # Heuristic: warn if lots of programs or suspicious types (kprobe/tracepoint/xdp)
  prog_types="$(bpftool prog show 2>/dev/null | grep -Eo 'type [a-zA-Z0-9_]+' | sort | uniq -c | sed 's/^ *//' || true)"
  echo "$prog_types" > "${output_dir}/bpftool_prog_types_summary.txt" 2>/dev/null || true
  if echo "$prog_types" | grep -Eq '(kprobe|tracepoint|xdp|cgroup_skb|kretprobe)'; then
    warn "BPF program types include kprobe/tracepoint/xdp/etc (review)"; add_risk "$W_EBPF_SUSPICIOUS" "Potentially high-risk BPF program types present"
  fi
else
  echo "bpftool not installed" > "${output_dir}/bpftool_prog_show.txt"
  info "Tip: sudo apt install bpftool (optional) for deeper BPF visibility"
fi

# XDP / TC hooks
run_cmd "ip_link_xdp.txt" bash -lc 'ip -details link show | sed -n "/xdp/,+6p" || true'
if have tc; then
  run_cmd "tc_qdisc.txt"  tc qdisc show
  run_cmd "tc_filters_all_devs.txt" bash -lc '
for dev in $(ip -o link show | awk -F": " "{print \$2}" | cut -d@ -f1); do
  echo "== dev $dev ==";
  tc filter show dev "$dev" 2>/dev/null || true;
done
'
fi

################################################################################
# (2) systemd generators persistence
################################################################################
banner "2) systemd generators persistence"
run_cmd "systemd_generators_dirs.txt" bash -lc 'ls -la /etc/systemd/system-generators /usr/lib/systemd/system-generators /run/systemd/system-generators 2>/dev/null || true'
run_cmd "systemd_generators_inventory.txt" bash -lc '
for d in /etc/systemd/system-generators /usr/lib/systemd/system-generators /run/systemd/system-generators; do
  [ -d "$d" ] || continue
  echo "== $d =="; ls -la "$d"
  find "$d" -maxdepth 1 -type f -print -exec sha256sum {} \; 2>/dev/null
done
'

if [ -d /etc/systemd/system-generators ] && [ "$(find /etc/systemd/system-generators -maxdepth 1 -type f 2>/dev/null | wc -l)" -gt 0 ]; then
  warn "Generators present in /etc/systemd/system-generators (higher suspicion)"; add_risk 35 "systemd generators in /etc"
fi
if [ -d /run/systemd/system-generators ] && [ "$(find /run/systemd/system-generators -maxdepth 1 -type f 2>/dev/null | wc -l)" -gt 0 ]; then
  warn "Generators present in /run/systemd/system-generators (ephemeral but can be malicious)"; add_risk 35 "systemd generators in /run"
fi

################################################################################
# (3) udev rules persistence
################################################################################
banner "3) udev rules persistence"
run_cmd "udev_rules_list.txt" bash -lc 'ls -la /etc/udev/rules.d /lib/udev/rules.d 2>/dev/null || true'
run_cmd "udev_rules_dump.txt" bash -lc 'grep -Rni . /etc/udev/rules.d 2>/dev/null || true'
run_cmd "udev_suspicious_grep.txt" bash -lc '
grep -RniE --binary-files=without-match "(RUN\\+=|curl|wget|nc |ncat|socat|bash -c|python -c|perl -e|/dev/tcp|base64|openssl enc)" /etc/udev/rules.d 2>/dev/null \
  | grep -vE "/etc/udev/rules.d/70-snap\\..*\\.rules" \
  || true
'
if [ -s "${output_dir}/udev_suspicious_grep.txt" ]; then
  sus "Suspicious patterns in udev rules"; head -n 20 "${output_dir}/udev_suspicious_grep.txt" | sed 's/^/  /'
  add_risk "$W_UDEV_SUSPICIOUS" "Suspicious commands/patterns found in udev rules"
else ok "No obvious suspicious patterns in udev rules"; fi

################################################################################
# (4) PAM / NSS / security modules abuse
################################################################################
banner "4) PAM/NSS/security modules checks"
run_cmd "pam_configs.txt" bash -lc 'ls -la /etc/pam.d 2>/dev/null; grep -Rni . /etc/pam.d 2>/dev/null || true'
run_cmd "nsswitch_conf.txt" bash -lc 'cat /etc/nsswitch.conf 2>/dev/null || true'
run_cmd "security_modules_list.txt" bash -lc 'for d in /lib/security /usr/lib/security /usr/lib64/security /usr/lib/*/security /usr/lib/*/*/security /usr/lib/x86_64-linux-gnu/security; do
  [ -d "$d" ] || continue
  echo "== $d =="; ls -la "$d"
done'
run_cmd "ldconfig_cache_head.txt" bash -lc 'ldconfig -p 2>/dev/null | head -n 250 || true'

# Heuristic: .so in /lib/security or /usr/lib*/security not owned by dpkg
pam_mod_report="${output_dir}/security_modules_dpkg_ownership.txt"; : > "$pam_mod_report"
for d in /lib/security /usr/lib/security /usr/lib64/security /usr/lib/x86_64-linux-gnu/security; do
  [ -d "$d" ] || continue
  while IFS= read -r so; do
    owner="$(dpkg_owner "$so")"
    echo "$so|$owner" >> "$pam_mod_report"
  done < <(find "$d" -maxdepth 1 -type f -name "*.so*" 2>/dev/null)
done

if grep -qE '\|$' "$pam_mod_report" 2>/dev/null; then
  warn "Some security modules have no dpkg owner (review security_modules_dpkg_ownership.txt)"
  add_risk "$W_PAM_SUSPICIOUS" "Security module(s) without dpkg ownership"
fi

################################################################################
# (5) Network namespace tricks
################################################################################
banner "5) Network namespace checks"
have lsns && run_cmd "lsns_net.txt" lsns -t net || echo "lsns not found" > "${output_dir}/lsns_net.txt"
run_cmd "ip_netns.txt" bash -lc 'ip netns list 2>/dev/null || true'
run_cmd "proc_netns_sample.txt" bash -lc 'ls -l /proc/*/ns/net 2>/dev/null | head -n 250 || true'

if have lsns; then
  netns_count="$(lsns -t net 2>/dev/null | awk 'NR>1{c++} END{print c+0}')"
  # Endpoint profile expects near 1 unless containers/VM tools
  if [ "$PROFILE" = "endpoint" ] && [ "$netns_count" -gt 2 ]; then
    warn "Multiple network namespaces detected ($netns_count)"; add_risk "$W_NETNS_UNEXPECTED" "Unexpected extra network namespaces"
  elif [ "$PROFILE" = "lab" ] && [ "$netns_count" -gt 6 ]; then
    warn "Many network namespaces detected ($netns_count)"; add_risk "$W_NETNS_UNEXPECTED" "High netns count (check if expected)"
  else
    ok "Network namespace count looks plausible ($netns_count)"
  fi
fi

################################################################################
# (6) Magic-packet / BPFDoor-ish hints (conntrack)
################################################################################
banner "6) Conntrack / odd UDP hints (if available)"
if have conntrack; then
  run_cmd "conntrack_list.txt" conntrack -L
  # Heuristic: large number of UDP entries might be normal; don't scream, just note
  udp_ct="$(conntrack -L 2>/dev/null | grep -ci ' udp ' || true)"
  [ "$udp_ct" -gt 0 ] && info "conntrack UDP entries: $udp_ct (review conntrack_list.txt if needed)"
else
  echo "conntrack not installed" > "${output_dir}/conntrack_list.txt"
fi

# Optional tcpdump sample is intentionally NOT run by default (privacy/noise).
echo "tcpdump sample disabled by default (privacy). Enable manually if needed." > "${output_dir}/tcpdump_note.txt"

################################################################################
# (7) Hidden network sockets refinements
################################################################################
banner "7) Hidden socket hunting (ss vs /proc/net + inode->PID mapping)"
run_cmd "proc_net_tcp.txt"  bash -lc 'cat /proc/net/tcp 2>/dev/null || true'
run_cmd "proc_net_tcp6.txt" bash -lc 'cat /proc/net/tcp6 2>/dev/null || true'
run_cmd "proc_net_udp.txt"  bash -lc 'cat /proc/net/udp 2>/dev/null || true'
run_cmd "proc_net_udp6.txt" bash -lc 'cat /proc/net/udp6 2>/dev/null || true'

have netstat && run_cmd "netstat_listen.txt" bash -lc 'netstat -lntup 2>/dev/null || true' || true
have lsof && run_cmd "lsof_listen.txt" bash -lc 'lsof -nP -i -sTCP:LISTEN 2>/dev/null || true' || true

proc_inode_file="${output_dir}/proc_socket_inodes.txt"; : > "$proc_inode_file"
awk 'NR>1 {print $10}' /proc/net/tcp  2>/dev/null >> "$proc_inode_file" || true
awk 'NR>1 {print $10}' /proc/net/tcp6 2>/dev/null >> "$proc_inode_file" || true
awk 'NR>1 {print $10}' /proc/net/udp  2>/dev/null >> "$proc_inode_file" || true
awk 'NR>1 {print $10}' /proc/net/udp6 2>/dev/null >> "$proc_inode_file" || true
sort -u "$proc_inode_file" -o "$proc_inode_file" 2>/dev/null || true

ss_inode_file="${output_dir}/ss_inodes.txt"; : > "$ss_inode_file"
ss -Hltunp -e 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^ino:/){gsub("ino:","",$i); print $i}}' | sort -u > "$ss_inode_file" || true

inode_map="${output_dir}/socket_inode_to_pid.txt"; : > "$inode_map"
inode_unknown="${output_dir}/socket_inodes_unmapped.txt"; : > "$inode_unknown"

if [ "$(id -u)" -eq 0 ]; then
  info "Mapping socket inodes -> PIDs (can take a moment)..."
  # Build a quick index of fd links to reduce readlink calls (best effort)
  # Still potentially heavy; acceptable for DFIR triage.
  while IFS= read -r inode; do
    [ -z "$inode" ] && continue
    found=0
    for fd in /proc/[0-9]*/fd/*; do
      link="$(readlink "$fd" 2>/dev/null || true)"
      if [ "$link" = "socket:[$inode]" ]; then
        pid="$(echo "$fd" | awk -F'/' '{print $3}')"
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
        echo "$inode|$pid|$exe|$cmd" >> "$inode_map"
        found=1
        break
      fi
    done
    [ "$found" -eq 0 ] && echo "$inode" >> "$inode_unknown"
  done < "$proc_inode_file"
else
  warn "Not root: inode->PID mapping likely incomplete."
fi
sort -u "$inode_map" -o "$inode_map" 2>/dev/null || true
sort -u "$inode_unknown" -o "$inode_unknown" 2>/dev/null || true

hidden_report="${output_dir}/hidden_socket_findings.txt"; : > "$hidden_report"
if [ -s "$ss_inode_file" ]; then
  comm -23 <(sort -u "$proc_inode_file") <(sort -u "$ss_inode_file") > "${output_dir}/proc_minus_ss_inodes.txt" 2>/dev/null || true
  if [ -s "${output_dir}/proc_minus_ss_inodes.txt" ]; then
    sus "Sockets present in /proc/net but not shown by ss -e (review)"; add_risk "$W_HIDDEN_SOCKET" "Sockets in /proc/net not shown by ss -e"
    echo "INODE|PID|EXE|CMDLINE" >> "$hidden_report"
    while IFS= read -r inode; do
      hit="$(ggrep -F "${inode}|" "$inode_map" 2>/dev/null | head -n 1 || true)"
      if [ -n "$hit" ]; then
        echo "$hit" >> "$hidden_report"
      else
        echo "$inode|UNKNOWN|UNKNOWN|Could not map inode to process" >> "$hidden_report"
        if [ "$(id -u)" -eq 0 ]; then add_risk "$W_INODE_NO_PID" "Unmapped socket inode (root) may indicate stealth/short-lived sockets"; fi
      fi
    done < "${output_dir}/proc_minus_ss_inodes.txt"
    head -n 12 "$hidden_report" | sed 's/^/  /'
  else
    ok "No /proc-net sockets missing from ss -e list detected"
  fi
else
  warn "ss -e inode extraction failed (cross-check limited)"
fi

################################################################################
# (8) Container/cloud hooks
################################################################################
banner "8) Container / cloud hooks inventory"
if have docker; then
  run_cmd "docker_ps.txt" docker ps -a
  run_cmd "docker_images.txt" docker images
  # Heuristic: endpoint profile with many containers -> note
  ccount="$(docker ps -a 2>/dev/null | awk 'NR>1{c++} END{print c+0}')"
  if [ "$PROFILE" = "endpoint" ] && [ "$ccount" -gt 5 ]; then
    warn "Many docker containers present ($ccount)"; add_risk "$W_CONTAINER_SUSPICIOUS" "Many docker containers on endpoint (review)"
  else
    info "Docker containers: $ccount"
  fi
else
  echo "docker not installed" > "${output_dir}/docker_ps.txt"
fi

if have crictl; then
  run_cmd "crictl_ps.txt" crictl ps -a
else
  echo "crictl not installed" > "${output_dir}/crictl_ps.txt"
fi

################################################################################
# Wrap-up: Top findings + score + summary + hashes + tarball
################################################################################
banner "Top findings (highest impact first)"
# sort findings by score desc
if [ "${#FINDINGS[@]}" -gt 0 ]; then
  printf "%s\n" "${FINDINGS[@]}" | sort -rn -k1.2,1.3 | head -n 10 | sed 's/^/  /'
else
  ok "No notable findings were scored."
fi

banner "Risk Evaluation"
if [ "$RISK_SCORE" -lt 30 ]; then
  ok "Risk Score=$RISK_SCORE -> Normal"
elif [ "$RISK_SCORE" -lt 70 ]; then
  warn "Risk Score=$RISK_SCORE -> Review recommended"
else
  sus "Risk Score=$RISK_SCORE -> Investigate ASAP"
fi

banner "Writing summary + hashes + bundle"
{
  echo "DFIR Hunt Summary (v3)"
  echo "Timestamp: $(date -Is)"
  echo "Profile: $PROFILE"
  echo "Host: $(hostname)"
  echo "User: $(id -un) uid=$(id -u)"
  echo "Risk Score: $RISK_SCORE"
  echo
  echo "== Top Findings =="
  if [ "${#FINDINGS[@]}" -gt 0 ]; then
    printf "%s\n" "${FINDINGS[@]}" | sort -rn -k1.2,1.3 | head -n 15
  else
    echo "(none)"
  fi
  echo
  echo "== Key Sysctl Flags =="
  echo "net.ipv4.ip_forward=$ip_fwd"
  echo "net.ipv6.conf.all.forwarding=$v6_fwd"
  echo "net.ipv4.conf.all.accept_redirects=$acc_redir"
  echo "net.ipv4.conf.all.send_redirects=$snd_redir"
  echo "net.ipv4.conf.all.rp_filter=$rp_filter"
  echo "net.ipv4.conf.all.accept_source_route=$src_route"
  echo
  echo "== Public listeners =="
  if [ -n "${public_listeners}" ]; then echo "$public_listeners"; else echo "(none)"; fi
  echo
  echo "== Notable report files =="
  echo "  network_pid_intel.txt"
  echo "  temp_execution_findings.txt"
  echo "  dpkg_integrity_report.txt"
  echo "  systemd_execstart_review.txt"
  echo "  cron_suspicious_grep.txt"
  echo "  systemd_generators_inventory.txt"
  echo "  udev_suspicious_grep.txt"
  echo "  security_modules_dpkg_ownership.txt"
  echo "  hidden_socket_findings.txt"
  echo "  bpftool_prog_show.txt (if bpftool installed)"
  echo
} > "${output_dir}/summary.txt" 2>/dev/null || true

( cd "$output_dir" && sha256sum * > SHA256SUMS.txt ) 2>/dev/null || true
tar -czf "${output_dir}.tar.gz" "$output_dir" 2>/dev/null || true

banner "Done"
ok "Evidence folder: $output_dir"
ok "Bundle: ${output_dir}.tar.gz"
ok "Summary: $output_dir/summary.txt"
ok "Hashes: $output_dir/SHA256SUMS.txt"
