🛡️ Smart DFIR Hunt
Linux Network & Persistence Triage Toolkit

Smart DFIR Hunt is a portable, incident-response oriented Bash scanner built to quickly answer the question:

> **Is something on this machine that should NOT be here?**

It focuses on live system reality, correlating processes, sockets, services, authentication modules, packages, and kernel mechanisms into an actionable risk profile.

No agents.  
No cloud.  
No dependencies beyond standard Linux tooling.

---

 🎯 Why this exists

During an incident you might not have:

- EDR
- Python frameworks
- internet access
- time

But you will always have **a shell**.

Smart DFIR Hunt is designed for that moment.

---

---

 🔬 What the tool analyzes

 🧠 Runtime execution visibility
- Processes with network access  
- Executable paths  
- Working directories  
- Parent/child lineage  
- Package ownership  

Because compromise = execution.

---

 🌐 Network exposure
- Public listeners  
- Established sessions  
- Socket statistics  
- Inode → PID mapping  
- `/proc` vs `ss` discrepancies  

Useful for spotting stealth bindings and hidden services.

---

 🔥 System attack surface
Rapid review of:

- IP forwarding  
- ICMP redirects  
- source routing  
- rp_filter  
- promiscuous interfaces  

---

 📦 Package integrity
For binaries tied to network activity:

- debsums verification  
- dpkg fallback  
- severity classification  

---

 🧬 Persistence mechanisms
Both traditional and modern.

 Systemd
Enabled services, timers, ExecStart review.

 Cron / at
Schedules + suspicious execution patterns.

 SSH
authorized_keys & daemon posture.

 Sudo / Polkit
Privilege escalation surfaces.

 ld.so.preload
Library injection.

 XDG / shell startup
User-level persistence.

 SUID / SGID
Privilege escalation footholds.

---

 🧱 Kernel / advanced evasion
- eBPF presence  
- bpffs  
- XDP  
- tc filters  
- loaded modules  

Because modern attackers avoid obvious userland traces.

---

 🧑‍💻 Authentication plane
- PAM configuration  
- NSS  
- security module ownership  

---

 🧩 Namespaces & containers
- network namespaces  
- Docker  
- CRI runtimes  

Prevents lab environments from triggering panic.

---

---

 ⚖️ Risk Scoring

Instead of shouting **COMPROMISED**, the tool assigns weights.

Results fall into:

🟢 Normal  
🟡 Review recommended  
🔴 Investigate ASAP  

This makes repeated runs measurable and comparable.

---

---

 🧾 Evidence Output

Each run produces:

- structured reports  
- SHA256 hashes  
- executive summary  
- compressed bundle  

Perfect for:

✔ escalation  
✔ documentation  
✔ sharing with responders  
✔ maintaining timelines  

---

---

 🎛️ Profiles

Endpoint-focused:

```bash
sudo PROFILE=endpoint bash smart_dfir_hunt_v3.sh
