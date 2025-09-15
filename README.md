# Linux RAM Forensics Student Lab — Ubuntu (Live & Offline) — Final Guide

*English with key Vietnamese terms in parentheses.*  
**Last updated:** 2025-09-10 03:30 (Asia/Ho_Chi_Minh)

**Scope:** Capture and analyze **Linux (Ubuntu) RAM** using **Volatility 3**. Acquisition focuses on live collection (AVML, LiME) and VM snapshots. **MemProcFS is not used for Linux analysis** (see Tooling Note).  
Steps: 0) Setup → 1) Live acquire → 2) Hash → 3) Prepare symbols → 4) Analyse (Volatility 3) → 5) Extract targets → 6) Report & CoC → 7) Checklist.

---

## Tooling Note (Lưu ý về công cụ)

- **MemProcFS limitation:** MemProcFS analyzes **Windows** images only. It can run *on* Linux, but it **does not parse Linux memory images**. For Ubuntu analysis, use **Volatility 3**.  
- Optional: You may still demonstrate MemProcFS on a Windows dump for comparison in a different lab.

---

## 0) Lab Objectives (Mục tiêu)

By the end of this lab, students can:

- Safely **acquire volatile memory** (RAM) from **Ubuntu** hosts (live systems and VMs).
- Generate and verify **SHA‑256 hashes** (băm SHA‑256) of memory images.
- Prepare required **Linux kernel symbols** for Volatility 3 (dwarf2json ISF).
- Analyse Linux dumps with **key Volatility 3 plugins** (processes, bash history, network, modules, open files, suspicious regions).
- Extract **target artifacts** (dump suspicious process memory, dump ELF binaries, list/maps, sockets).
- Document findings and maintain a **Chain of Custody (Chuỗi bàn giao chứng cứ)**.

> **Ethics & Legal (Đạo đức & Pháp lý):** Perform these labs **only** on systems you own or have explicit authorization to examine. Memory captures can contain **PII, credentials, keys**. Treat all outputs as **evidence**.

---

## 1) Lab Setup (Chuẩn bị)

**Hardware/VM:** Ubuntu 22.04/24.04 victim VM (≥4–8 GB RAM) and a separate **forensic workstation**/USB drive for evidence.  
**Accounts:** `sudo` on victim.  
**Destination:** A clean external path, e.g., `/mnt/usb/Evidence/CASE-LIN-001/` (mount with `ro,noexec,nodev,nosuid` where applicable).  
**Tools (Công cụ):**

- **AVML** (Acquire Volatile Memory for Linux) — user‑space, low footprint.
- **LiME** (Linux Memory Extractor) — kernel module; produces RAW/LiME format.
- **Volatility 3** (Python 3.10+ recommended).
- **dwarf2json** — generate Linux **ISF** symbol tables.
- Hashing: `sha256sum` (CLI).

**Good practice:**

- Minimize interaction with the target prior to capture.
- Ensure **free space ≥ RAM size** at destination.
- Record **tool versions**, **exact commands**, **timestamps** (TZ: Asia/Ho_Chi_Minh or GMT/UTC).

---

## 2) Live Acquisition (Thu thập bộ nhớ trực tiếp)

### Method — AVML (Ưu tiên)
>
> Works on modern kernels without loading a module.

```bash
# On the Ubuntu target (sudo)
DEST=/mnt/usb/Evidence/CASE-LIN-001
sudo mkdir -p "$DEST"
sudo avml "$DEST/mem.avml"        # default AVML format (LiME-compatible layer)
# Optional: raw output (larger file), some workflows prefer:
# sudo avml --raw "$DEST/mem.raw"
sync
```

**Notes**

- Prefer **uncompressed** output for smoother analysis.
- Keep the terminal transcript or `script` log as evidence.

**VM Snapshot Alternative (KVM/QEMU)**

```bash
# On the host (not inside the guest), quick snapshot of VM memory only
sudo virsh dump --memory-only --verbose <vm-name> /mnt/usb/Evidence/CASE-LIN-001/mem.virsh
```

> **Do not** rely on Linux hibernation files for memory analysis in this lab. Hibernation saves to **swap**, not a dedicated `hiberfil.sys`, and is unreliable for reconstruction. Treat swap captures as **secondary** artefacts only.

---

## 3) Integrity — Hashing (Băm SHA‑256)

Compute two independent hashes when possible (redundancy). Here we use `sha256sum` and also store to text.

```bash
cd /mnt/usb/Evidence/CASE-LIN-001
sha256sum mem.avml   | tee hash_mem_avml.txt
# or
sha256sum mem.raw    | tee hash_mem_raw.txt
sha256sum mem.lime   | tee hash_mem_lime.txt
sha256sum mem.virsh  | tee hash_mem_virsh.txt
```

---

## 4) Prepare Linux Symbols (Chuẩn bị bảng ký hiệu Linux cho Volatility 3)

Volatility 3 needs a matching **kernel symbol table (ISF)** for Linux.

### 4.1 Get the vmlinux with debug symbols (Ubuntu)

On a reference Ubuntu VM **matching the dump’s kernel**, install debug packages and locate `vmlinux`:

```bash
# Enable Ubuntu debug symbol repository if needed (ddebs)
sudo apt install ubuntu-dbgsym-keyring || true
# Example (paths may vary by release/kernel flavour):
sudo apt update
sudo apt install -y linux-image-$(uname -r)-dbgsym

# Locate the debug image (typical):
ls -l /usr/lib/debug/boot/vmlinux-$(uname -r)
# System.map (optional but helpful):
ls -l /boot/System.map-$(uname -r)
```

### 4.2 Build ISF with dwarf2json

```bash
# Build dwarf2json once (on analyst box)
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build .    # requires golang

# Generate the symbol table (ISF JSON), optionally compress
dwarf2json linux   --elf /usr/lib/debug/boot/vmlinux-<kernel>   --system-map /boot/System.map-<kernel>   > ubuntu-<kernel>.json

# Place under Volatility 3 symbols (so auto-discovery can find it)
mkdir -p ~/.local/share/volatility3/symbols/linux
mv ubuntu-<kernel>.json ~/.local/share/volatility3/symbols/linux/
```

> If kernel build differs from the dump, first identify it with `banners.Banners` (see §5.1), then fetch the **matching** debug vmlinux and regenerate the ISF.

---

## 5) Analysis with Volatility 3 (Phân tích với Volatility 3)

### 5.1 Triage — Identify OS/Kernel & Sanity Checks

```bash
# Identify likely kernel banner strings (helps confirm the right ISF)
python3 vol.py -f mem.avml banners.Banners

# If you have multiple symbol dirs:
python3 vol.py --symbol-dirs ~/.local/share/volatility3/symbols -f mem.avml banners.Banners
```

### 5.2 Core Enumeration

```bash
# Processes
python3 vol.py -f mem.avml linux.pslist
python3 vol.py -f mem.avml linux.pstree
python3 vol.py -f mem.avml linux.psscan    # find hidden/terminated

# Bash history (from memory)
python3 vol.py -f mem.avml linux.bash

# Kernel modules & integrity
python3 vol.py -f mem.avml linux.lsmod
python3 vol.py -f mem.avml linux.check_creds
python3 vol.py -f mem.avml linux.capabilities

# Open files / memory maps
python3 vol.py -f mem.avml linux.lsof      # per-process FDs
python3 vol.py -f mem.avml linux.proc.Maps # VMA maps

# Network
python3 vol.py -f mem.avml linux.sockstat  # sockets & endpoints
```

### 5.3 Suspicious Indicators (Hunting)

```bash
# Potential injected/executable regions (deprecated name maintained in some builds)
python3 vol.py -f mem.avml linux.malfind

# Quick YARA sweep of memory (point to a rules folder)
python3 vol.py -f mem.avml yarascan.YaraScan --yara-rules /path/to/rules.yar

# Timelined view (when available)
python3 vol.py -f mem.avml timeliner.Timeliner
```

> Tip: Add `-r csv` to export CSV, or `-r jsonl` for structured outputs. Save to `/mnt/usb/Evidence/CASE-LIN-001/analysis/`.

---

## 6) Extract Target Artifacts (Trích xuất dữ liệu mục tiêu)

Create an extraction folder and use built‑in dump options where available.

```bash
OUT=/mnt/usb/Evidence/CASE-LIN-001/extractions
mkdir -p "$OUT"

# 6.1 Dump suspicious processes (newer Vol3 supports --dump on linux.pslist)
python3 vol.py -f mem.avml -o "$OUT/proc" linux.pslist --pid 1234 --dump

# 6.2 Dump ELF objects discovered in RAM
python3 vol.py -f mem.avml -o "$OUT/elfs" linux.elfs --dump

# 6.3 Dump mapped regions by VMA (targeted)
python3 vol.py -f mem.avml -o "$OUT/maps" linux.proc.Maps --pid 1234 --dump

# 6.4 Save bash history artefacts
python3 vol.py -f mem.avml -r csv -o "$OUT" linux.bash > "$OUT/linux_bash.csv"

# 6.5 Export socket info (for IOC correlation)
python3 vol.py -f mem.avml -r csv linux.sockstat > "$OUT/linux_sockstat.csv"
```

After each extraction, compute **SHA‑256** for chain‑of‑custody:

```bash
find "$OUT" -type f -exec sha256sum "{} " \; | tee "$OUT/hashes_extractions.txt"
```

---

## 7) Documentation & Chain of Custody (Ghi chép & CoC)

### 7.1 Lab Logbook (Nhật ký)

Record: **Case ID**, Examiner, Hostname, Kernel, RAM size, Tools/versions, Commands, Paths, Hashes, Key findings, Timestamps.

**Template:**

```text
Case ID: CASE-LIN-001
Examiner: <Name> | Student ID: <ID> | Team: <>
Host: UBUNTU-VM | Kernel: 5.15.0-XX-generic | RAM: 8 GB
Timezone: UTC+7 (Asia/Ho_Chi_Minh)

[Acquisition]
2025-09-10 10:05 Start AVML
2025-09-10 10:08 End AVML → /mnt/usb/Evidence/CASE-LIN-001/mem.avml (8,589,934,592 bytes)
SHA‑256: <hash>

[Analysis]
Vol3 banners.Banners / linux.pslist / linux.bash / linux.sockstat / linux.lsof / linux.malfind …
Key findings: <summary>

[Extractions]
Dumped PID 1234 → …/extractions/proc/
ELFs → …/extractions/elfs/
Hashes: …/extractions/hashes_extractions.txt

[Conclusions]
<high‑level findings tied to objectives>
```

### 7.2 Chain of Custody (Chuỗi bàn giao chứng cứ)

| Evidence ID | Case ID | Description | Acquired By | Date/Time (TZ) | Location/Media | SHA‑256 | Released To | Signature |
|---|---|---|---|---|---|---|---|---|
| EV‑LIN‑001 | CASE‑LIN‑001 | RAM image `mem.avml` | <Name> | 2025‑09‑10 10:08 (+07) | USB S/N: XXX | `<hash1>` | <TA> | ___ |
| EV‑LIN‑002 | CASE‑LIN‑001 | Extractions (PID 1234, ELFs) | <Name> | 2025‑09‑10 11:00 (+07) | USB S/N: XXX | `<hash2>` | <TA> | ___ |

**Storage:** Use **read‑only** or WORM‑like media; seal evidence with tamper‑evident labels; record seal numbers.

---

## 8) Deliverables (Nộp bài)

- Memory image (`mem.avml` or `mem.raw`/`mem.lime`/`mem.virsh`).
- Hash reports (`hash_mem_*.txt`, `hashes_extractions.txt`).
- Volatility CSV/JSON outputs (plugins used).
- Extracted artifacts (dumped processes/ELFs) with hashes.
- Final **Lab Report** (Markdown/PDF) including CoC.

---

## 9) Troubleshooting (Khắc phục)

- **No output / plugin fails:** Usually a **symbol mismatch**. Re‑run `banners.Banners`, rebuild ISF from the **exact** `vmlinux`, and retry with `--symbol-dirs`.
- **Permission denied (AVML/LiME):** Ensure `sudo`, destination writable, and module matches kernel headers.
- **Huge files:** Prefer AVML default or LiME `format=lime`; avoid compression during first‑pass analysis.
- **Inconsistent artefacts:** Live acquisition can change memory. Capture as early as possible; minimise activity; consider VM memory‑only dump via `virsh` for lab repeatability.
- **MemProcFS on Linux dumps?** Not supported. Use Volatility 3 only for Ubuntu.

---

## 10) Checklist (Tự kiểm)

- [ ] Acquired RAM with **AVML** (or **LiME** / `virsh dump` for VMs)  
- [ ] Generated **SHA‑256** for the image(s)  
- [ ] Prepared matching **Linux ISF** (dwarf2json)  
- [ ] Ran key **Volatility 3** plugins (banners, pslist/pstree/psscan, bash, lsmod, lsof, proc.Maps, sockstat, malfind)  
- [ ] Extracted targets (process dumps, ELFs) and hashed results  
- [ ] Completed **Lab Report** and **Chain of Custody**

---

## 11) Cross-Tool Verification (Kiểm chứng bằng công cụ khác)

To avoid **single-tool dependence**, perform independent scans on the raw memory image
alongside Volatility 3. This mimics the role of MemProcFS in Windows labs.

### 11.1 bulk_extractor (Carving & Pattern Scanning)

`bulk_extractor` scans raw memory for artefacts such as URLs, email addresses, credit
card numbers, file headers, and compressed data.

```bash
# Create output directory
mkdir -p /mnt/usb/Evidence/CASE-LIN-001/crosscheck/bulk_extractor

# Run bulk_extractor on AVML/RAW/LiME dump
bulk_extractor -o /mnt/usb/Evidence/CASE-LIN-001/crosscheck/bulk_extractor \
  /mnt/usb/Evidence/CASE-LIN-001/mem.avml

```

**Notes**: Outputs appear in text files (e.g., url.txt, email.txt) inside the chosen directory.
Use them to cross-validate Volatility findings such as C2 addresses or suspicious
file references.

### 11.2 YARA CLI (Signature-Based Detection)

Run YARA directly on the dump to detect known malware strings or patterns. This provides
an independent check against Volatility’s yarascan

# Example YARA rule file

```bash
cat > ransomware_rules.yar <<'EOF'
rule Detect_Ransomware_Behavior {
  meta:
    author = "IR Lab"
    description = "Detects common ransomware commands"
  strings:
    $s1 = "vssadmin delete shadows" nocase
    $s2 = "bcdedit /set" nocase
    $s3 = "cipher /w" nocase
  condition:
    any of ($s*)
}
EOF

# Run yara on memory dump
yara -r ransomware_rules.yar /mnt/usb/Evidence/CASE-LIN-001/mem.avml \
  > /mnt/usb/Evidence/CASE-LIN-001/crosscheck/yara_hits.txt

```

### 11.3 Reporting

Compare bulk_extractor URLs/emails with linux.sockstat or bash plugin outputs.

Confirm YARA hits align with Volatility’s yarascan.

Record results in the Evidence Logbook and include artefacts + SHA-256 hashes
