Chronological Runbook (matches current script order)

0) Preconditions

Best practice: run as root so the script can:

read full firewall state

map socket inodes → PIDs reliably

read more persistence locations without permission gaps

sudo -v
sudo PROFILE=endpoint bash smart_dfir_hunt_v3.sh

What happens first:

set -u → script errors on unset vars (safer than silently failing)

umask 077 → outputs are created with restrictive permissions (owner-only)

1) Output folder setup

The script creates a timestamped evidence folder:

forensic_hunt_YYYY-MM-DD_HH-MM-SS

Everything it collects gets written in there. At the end it creates:

SHA256SUMS.txt

forensic_hunt_....tar.gz

Under the hood:

timestamp="$(date ...)", mkdir -p "$output_dir"

2) Profile selection (PROFILE=endpoint|lab)
What it is

A tuning knob for alert/noise levels.

How it works

It doesn’t change what gets collected — it changes risk weights used when deciding what’s “worth screaming about.”

PROFILE=endpoint (default): stricter, higher weights for stealthy/rare things

PROFILE=lab: more tolerant (containers, netns, BPF are common)

Usage
sudo PROFILE=endpoint bash smart_dfir_hunt_v3.sh
sudo PROFILE=lab bash smart_dfir_hunt_v3.sh
Differences (script-accurate)

Lab lowers these weights:

W_EBPF_PRESENT 15 → 5

W_EBPF_SUSPICIOUS 40 → 20

W_NETNS_UNEXPECTED 10 → 5

W_CONTAINER_SUSPICIOUS 15 → 5

W_PUBLIC_LISTENER 10 → 7

W_UNUSUAL_PATH 10 → 7

3) Optional allowlisting (BASELINE_ALLOWLIST_FILE)
What it is

Regex suppression for “known-good but noisy” paths/strings.

What it affects

When the script is reviewing:

systemd units (service name or ExecStart path)

network processes (exe path or cmdline)

If something matches your allowlist regex → it prints ALLOWLISTED and skips risk scoring.

Usage
sudo BASELINE_ALLOWLIST_FILE=/path/to/allowlist_regex.txt bash smart_dfir_hunt_v3.sh

Under the hood:

Reads file lines, strips comments, trims whitespace

Stores regex lines in ALLOWLIST_REGEX[]

is_allowlisted() runs grep -Eq against each regex

4) Optional baseline learning (LEARN_BASELINE + BASELINE_FILE)
What it is

A “learn mode” that records network process executable paths as a baseline.

What it affects

Only the Network PID attribution section:

if a process exe is in your baseline file → prints Baseline EXE and suppresses further flags.

Usage
sudo LEARN_BASELINE=1 BASELINE_FILE=baseline_exec_allowlist.txt bash smart_dfir_hunt_v3.sh

Under the hood:

After writing network_pid_intel.txt, it extracts column 4 (EXE) and writes a sorted list to BASELINE_FILE.

What the script does (chronological)
5) Core evidence collection (writes files)
5.1 Host identity & OS

Files created:

system_info.txt (uname, hostnamectl, uptime, timestamp)

os_release.txt

5.2 Network state snapshot

Files created:

ip_addr.txt, ip_link.txt, ip_link_stats.txt

routing_table_main.txt, routing_table_all.txt, ip_rule.txt, ip_neigh.txt

5.3 DNS + proxy posture

Files created:

dns_resolv_conf.txt

resolvectl_status.txt (only if resolvectl exists)

nmcli_dev_show.txt (only if nmcli exists)

proxy_env.txt (http_proxy etc.)

5.4 Socket inventories (multiple viewpoints)

Files created:

ss_tulnp.txt, ss_tunap.txt

ss_established_tcp.txt, ss_socket_summary.txt

lsof_i.txt (if lsof exists)

netstat_plant.txt (if netstat exists)

Under the hood:

Uses run_cmd wrapper which writes:

command line

ISO timestamp

command output (stdout+stderr)

6) Firewall evidence (writes files)

Captures whatever is available:

ufw_status_verbose.txt (if ufw)

nft_ruleset.txt (if nft)

iptables_save.txt (if iptables-save)

7) Process inventory (writes file)

Creates:

process_tree.txt using ps --forest

This is your “who spawned who” baseline.

8) LIVE TRIAGE: network attack surface (prints + scores)

This is the first “judgement” section. It reads sysctls and checks exposure.

8.1 sysctl reads

Reads:

net.ipv4.ip_forward

net.ipv6.conf.all.forwarding

net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.send_redirects

net.ipv4.conf.all.rp_filter

net.ipv4.conf.all.accept_source_route

It prints OK/WARN/SUSPICIOUS and calls add_risk accordingly.

8.2 Public listeners

Detects services bound to:

0.0.0.0:*

:: / [::]

Under the hood:

ss -Hltunp | awk ... filters binding address field

8.3 Promiscuous mode

Creates:

promiscuous_mode.txt
Warns if any interface has PROMISC.

9) LIVE TRIAGE: network PID attribution (writes + scores)

Creates:

network_pid_intel.txt

It:

extracts PIDs from ss -tunap

for each PID collects:

PPID, USER

/proc/PID/exe real path

cwd

cmdline

trust class (based on path)

dpkg owner (via dpkg-query -S)

Trust classification (script-accurate)

SUSPICIOUS: /tmp, /var/tmp, /dev/shm

TRUSTED: /usr/bin, /bin, /usr/lib, /lib, /usr/libexec, etc.

LIKELY_OK: /snap

UNUSUAL: /opt, /home, or anything else

Risk logic

temp/shm execution → higher risk

unusual path + no dpkg owner → additional risk

trusted path but no dpkg owner → warns (could be custom drop-in)

Baseline logic

if exe matches BASELINE_FILE line exactly → “Baseline EXE”

if allowlisted → “ALLOWLISTED”

10) LIVE TRIAGE: temp execution + deleted executables (writes + scores)

Creates:

temp_execution_findings.txt

It walks /proc/* and checks:

exe path under tmp/shm

cwd under tmp/shm

if /proc/PID/exe symlink shows (deleted)

Then:

prints a short preview if findings exist

increases risk score, and extra points if deleted exe is running

11) LIVE TRIAGE: package integrity of network-facing packages (writes + scores)

Creates:

network_pkgs.txt (derived from dpkg owner lines)

dpkg_integrity_report.txt

Logic:

If debsums exists → uses it

Else uses dpkg --verify

Then it classifies drift:

INFO: config changes (c)

SUSPICIOUS: checksum change + file under (bin|sbin|lib|lib64)

WARN: other mismatches

12) Persistence hunting (classic)

This section is “broad persistence surfaces”.

12.1 systemd units/timers

Writes:

systemd_enabled_services.txt

systemd_enabled_timers.txt

systemd_running_services.txt

systemd_running_timers.txt

systemd_execstart_review.txt

Then it reviews ExecStart:

finds first absolute path from ExecStart

classifies trust

allowlist can suppress

unusual ExecStart → risk

temp ExecStart → high risk

12.2 cron + at

Writes:

cron_system_dirs.txt, crontab_system.txt

cron_spool.txt, cron_user_list.txt

atq.txt (if atq exists)

cron_suspicious_grep.txt

The grep looks for common implant keywords:
curl wget nc socat bash -i python -c perl -e /dev/tcp base64 openssl enc mkfifo authorized_keys

12.3 SSH posture

Writes:

sshd_config_or_effective.txt

authorized_keys_root.txt

authorized_keys_all_users.txt

12.4 sudoers + polkit

Writes:

sudoers.txt

polkit_rules.txt

12.5 ld.so.preload + LD_* hints

Writes:

ld_so_preload.txt

ld_preload_env_grep.txt
Flags if /etc/ld.so.preload is non-empty.

12.6 autostart + shell hooks

Writes:

xdg_autostart_system.txt

xdg_autostart_user.txt

shell_profile_hooks.txt

12.7 kernel modules

Writes:

lsmod.txt

modules_load_conf.txt

12.8 SUID/SGID scan

Writes:

suid_sgid_bins.txt

suid_sgid_suspicious_paths.txt (filters to /tmp,/home,/opt,/dev/shm,…)

13) Advanced additions (requested 1–8)
13.1 eBPF / bpffs / XDP / tc

Writes:

mounts_bpf.txt

sys_fs_bpf_listing.txt

bpftool_* files if bpftool exists

bpftool_prog_types_summary.txt

ip_link_xdp.txt

tc_qdisc.txt, tc_filters_all_devs.txt (if tc exists)

Scores:

bpffs mounted → W_EBPF_PRESENT

suspicious BPF types (kprobe/tracepoint/xdp/cgroup/kretprobe) → W_EBPF_SUSPICIOUS

13.2 systemd generators

Writes:

systemd_generators_dirs.txt

systemd_generators_inventory.txt
Flags if generators exist in:

/etc/systemd/system-generators

/run/systemd/system-generators

13.3 udev rules

Writes:

udev_rules_list.txt

udev_rules_dump.txt

udev_suspicious_grep.txt

It greps for RUN+= and common download/exec patterns and excludes snap noise:

ignores /etc/udev/rules.d/70-snap.*.rules

13.4 PAM/NSS/security module dirs

Writes:

pam_configs.txt

nsswitch_conf.txt

security_modules_list.txt

ldconfig_cache_head.txt

security_modules_dpkg_ownership.txt

Under the hood:

enumerates security module dirs

finds *.so*

runs dpkg-query -S per module

flags any module with no dpkg owner

13.5 Network namespaces

Writes:

lsns_net.txt (if lsns exists)

ip_netns.txt

proc_netns_sample.txt

Flags based on profile:

endpoint: >2 netns warns

lab: >6 netns warns

13.6 Conntrack / odd UDP hints

Writes:

conntrack_list.txt if conntrack exists

else writes “not installed”
Also writes:

tcpdump_note.txt (tcpdump intentionally not executed)

13.7 Hidden socket hunting (proc vs ss + inode mapping)

Writes:

proc_net_tcp.txt, proc_net_tcp6.txt, proc_net_udp.txt, proc_net_udp6.txt

netstat_listen.txt (if netstat)

lsof_listen.txt (if lsof)

proc_socket_inodes.txt

ss_inodes.txt

socket_inode_to_pid.txt

socket_inodes_unmapped.txt

proc_minus_ss_inodes.txt

hidden_socket_findings.txt

Under the hood:

extracts inodes from /proc/net/*

extracts inodes from ss -e

computes /proc minus ss

attempts to map inode → pid by scanning /proc/*/fd/* symlinks (root helps)

unmapped inode adds risk

Note: your pasted script has ggrep here:
hit="$(ggrep -F "${inode}|" "$inode_map" ...)"
On Ubuntu, ggrep usually does not exist (that’s a macOS/Homebrew thing).
Replace ggrep with grep to avoid breaking this section.

13.8 Containers / cloud hooks

Writes:

docker_ps.txt, docker_images.txt if docker exists

crictl_ps.txt if crictl exists

Flags if endpoint has many containers (>5).

14) Wrap-up: scoring, summary, hashes, tarball

Prints:

Top findings (sorted by point value)

Risk score bucket: Normal / Review / Investigate ASAP

Writes:

summary.txt

SHA256SUMS.txt

forensic_hunt_....tar.gz

Under the hood:

hashes every file in the evidence folder

bundles everything into tar.gz

One-screen “Option Differences” (clean)
PROFILE=endpoint

stricter scoring for BPF/netns/container/public listeners/unusual paths

best for real workstation/server triage

PROFILE=lab

reduces those weights

best for homelab/dev environments

LEARN_BASELINE=1

creates baseline file from network-attributed EXE paths

does not affect collection; affects later comparisons

BASELINE_FILE=...

name/path for the baseline list

BASELINE_ALLOWLIST_FILE=...

regex suppressions for:

systemd suspicious ExecStart checks

network PID attribution checks
