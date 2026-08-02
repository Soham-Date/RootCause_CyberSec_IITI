# Linux Privilege-Escalation Reconnaissance Utility

## Overview

`linux-privesc-recon.sh` is a standalone, dependency-free Bash script
that audits a Linux system for common local privilege-escalation
indicators. It is the reconnaissance component of RootCause, used to
triage a target environment before or alongside manual CVE-specific
analysis — surfacing the kinds of misconfigurations and exposures that
the project's individual CVE writeups (Dirty Cow, PwnKit, Dirty Pipe,
Copy Fail, DirtyFrag) exploit in practice.

The script is read-only. It never modifies the target system; it only
reports.

---

## Tool Details

- **Type:** Local reconnaissance / audit script
- **Language:** Bash (4+), no external dependencies beyond coreutils /
  findutils
- **Access Required:** Local shell access (unprivileged or root)
- **Output:** Colorized terminal report; optional plain-text file via `-o`
- **Scope:** Kernel version, filesystem permissions, sudo configuration,
  installed package versions, and file capabilities

---

## Checks Performed

| # | Area | What it does |
|---|---|---|
| 1 | Kernel CVE exposure | Compares `uname -r` (and, where relevant, loaded kernel modules / modprobe blacklists) against known vulnerable ranges for Dirty Cow (CVE-2016-5195), Dirty Pipe (CVE-2022-0847), Copy Fail (CVE-2026-31431), and DirtyFrag (CVE-2026-43284 / CVE-2026-43500) |
| 2 | SUID / SGID binaries | Walks the filesystem for `4000`/`2000` permission bit binaries, filters expected system binaries, and flags GTFOBins-listed binaries that grant an instant privileged shell if SUID |
| 3 | World-writable cron & sensitive paths | Checks `/etc/cron*`, `/var/spool/cron`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`, `/etc/ssh/sshd_config`, `/root`, and flags any writable directory in `$PATH` (PATH-hijack vector) |
| 4 | Sudo configuration | Parses `sudo -n -l` and `/etc/sudoers(.d)` for `NOPASSWD` rules, blanket `ALL=(ALL) ALL` grants, dangerous `env_keep` entries (`LD_PRELOAD`/`LD_LIBRARY_PATH`), GTFOBins-listed sudo-able commands, and checks the `sudo` binary version against CVE-2021-3156 |
| 5 | Vulnerable package versions | Detects PwnKit (CVE-2021-4034) exposure via `pkexec` presence, SUID bit, and polkit package version; records versions of `sudo`, `systemd`, `openssh`, `util-linux` |
| 6 | Non-standard capabilities | Uses `getcap -r /` to find files with extended POSIX capabilities and flags dangerous ones (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`, `cap_sys_ptrace`, etc.) |

---

## Detection Methodology

Each check works by comparing observed system state against a
known-bad baseline rather than by attempting exploitation:

- **Version-range matching** for kernel and package CVEs, using
  publicly documented fixed versions where available (e.g. Dirty Pipe
  fixed at 5.16.11/5.15.25/5.10.102; Copy Fail fixed at 6.18.22/6.19.12).
  Where an exact per-branch fixed version isn't publicly documented
  (e.g. DirtyFrag's ongoing distro-by-distro rollout), the script falls
  back to a broader version floor plus a runtime signal — checking
  whether the specific vulnerable kernel modules are loaded and whether
  the published interim mitigation (modprobe blacklist) is already in
  place — and flags the result as MEDIUM confidence rather than a
  confirmed verdict.
- **Baseline diffing** for SUID/SGID binaries and capabilities: a known
  list of expected system binaries is excluded from findings so the
  output highlights anomalies rather than noise.
- **Static config parsing** for sudoers and cron, looking for the
  specific misconfiguration patterns documented in privilege-escalation
  research (NOPASSWD, environment variable preservation, world-writable
  targets).

No exploit code is included or executed at any point; the script's job
ends at identifying exposure, matching the "Root Cause" style of
analysis used elsewhere in this project without performing the
exploitation step itself.

---

## Usage

```bash
chmod +x linux-privesc-recon.sh

# Run and print to screen
./linux-privesc-recon.sh

# Run and also save a plain-text report
./linux-privesc-recon.sh -o report.txt

# Quiet mode: findings only, no section banners or OK lines
./linux-privesc-recon.sh -q
```

Run as an unprivileged user for the most realistic attacker's-eye view;
running as root sees more (root-only sudoers detail, unreadable files)
but will over-report writable-path findings, since root can write to
nearly everything by definition.

---

## Sample Output

```
== Kernel CVE Exposure ==
[INFO] Detected kernel version: 6.18.5
[OK]   Dirty Cow (CVE-2016-5195): kernel version is >= 4.8.3 (likely patched, verify distro backport status if paranoid).
[OK]   Dirty Pipe (CVE-2022-0847): kernel branch (6.18.5) outside the affected 5.x range.
[HIGH] Copy Fail (CVE-2026-31431): kernel 6.18.5 is in the vulnerable 6.18.x range (< 6.18.22). Actively exploited (CISA KEV); patch immediately.
[MED]  DirtyFrag (CVE-2026-43284 / CVE-2026-43500): kernel 6.18.5 is >= 4.14 (in the broad affected range) but esp4/esp6/rxrpc are not currently loaded and no blacklist was found.
```

Severity levels: **HIGH** (strong, specific indicator of a working
privesc path), **MEDIUM** (worth investigating, not conclusive alone),
**INFO** (context), **OK** (checked, nothing concerning found).

---

## Impact / Value to the Project

The recon utility gives RootCause a repeatable way to confirm that an
isolated environment is actually in the vulnerable state a given CVE
module expects before the exploitation phase begins — and afterward, to
confirm a patch or mitigation actually closed the exposure. It also
generalizes beyond the five target CVEs: the SUID, sudo, cron, and
capability checks catch the broader class of misconfigurations that
show up in real-world privilege-escalation research independent of any
single CVE.

---

## Limitations

- Version-based checks are heuristic. Distro kernels and packages
  frequently backport fixes without changing the version string a
  script can see, so results should be confirmed against the distro's
  own security advisory before being treated as final.
- Point-in-time snapshot only, not continuous monitoring.
- Copy Fail and DirtyFrag are recent (April–May 2026) and patch rollout
  was still in progress across some distributions as of this writing;
  the DirtyFrag check in particular relies on module/mitigation
  presence rather than a confirmed fixed-version cutoff.
- Identifies exposure only — it does not confirm exploitability. Any
  HIGH finding should be validated deliberately in an isolated test
  environment, consistent with the rest of this project's workflow.

---

## References

- CVE-2016-5195 (Dirty Cow) — MITRE / NVD
- CVE-2021-4034 (PwnKit) — Qualys Security Advisory, MITRE / NVD
- CVE-2022-0847 (Dirty Pipe) — MITRE / NVD
- CVE-2026-31431 (Copy Fail) — Theori disclosure, CISA KEV catalog
- CVE-2026-43284 / CVE-2026-43500 (DirtyFrag) — public disclosure by
  Hyunwoo Kim (oss-security), vendor security advisories
- GTFOBins (gtfobins.github.io) — reference list for SUID/sudo/capability
  privilege-escalation vectors
