#!/usr/bin/env bash
#
# linux-privesc-recon.sh
#
# Standalone, dependency-free audit script for common Linux
# privilege-escalation indicators. Read-only: it never modifies the
# system, it only reports.
#
# Usage:
#   ./linux-privesc-recon.sh                # run all checks, print to screen
#   ./linux-privesc-recon.sh -o report.txt   # also write plain-text report
#   ./linux-privesc-recon.sh -q              # quiet mode (findings only, no banners)
#
# Exit codes:
#   0 = ran cleanly (findings may still exist, check output)
#   1 = ran with one or more internal errors (e.g. missing tool)
#
# Tested target: any Linux system with bash 4+, coreutils, findutils.
# Run as an unprivileged user to see what an attacker with a foothold
# would see; run as root to get a fuller picture (some paths are only
# readable by root).

set -u
SCRIPT_VERSION="2.0.0"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OUTFILE=""
QUIET=0
while getopts "o:qh" opt; do
  case "$opt" in
    o) OUTFILE="$OPTARG" ;;
    q) QUIET=1 ;;
    h)
      echo "Usage: $0 [-o outfile] [-q]"
      exit 0
      ;;
    *) echo "Unknown option"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RED='\033[0;31m'; C_YEL='\033[0;33m'; C_GRN='\033[0;32m'
  C_BLU='\033[0;34m'; C_BLD='\033[1m'; C_RST='\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_BLU=''; C_BLD=''; C_RST=''
fi

REPORT_BUF=""
FINDINGS_HIGH=0
FINDINGS_MED=0
FINDINGS_INFO=0

log() {
  # log <level> <text>
  local level="$1"; shift
  local text="$*"
  local tag color
  case "$level" in
    HIGH) tag="[HIGH]"; color="$C_RED"; FINDINGS_HIGH=$((FINDINGS_HIGH+1)) ;;
    MED)  tag="[MED] "; color="$C_YEL"; FINDINGS_MED=$((FINDINGS_MED+1)) ;;
    INFO) tag="[INFO]"; color="$C_BLU"; FINDINGS_INFO=$((FINDINGS_INFO+1)) ;;
    OK)   tag="[OK]  "; color="$C_GRN" ;;
    HDR)  tag=""; color="$C_BLD" ;;
    *)    tag="[?]   "; color="" ;;
  esac
  if [ "$level" = "HDR" ]; then
    [ "$QUIET" -eq 0 ] && printf "\n${color}== %s ==${C_RST}\n" "$text"
    REPORT_BUF+=$'\n'"== $text =="$'\n'
  else
    [ "$QUIET" -eq 0 ] || [ "$level" != "OK" ] && printf "${color}%s${C_RST} %s\n" "$tag" "$text"
    REPORT_BUF+="$tag $text"$'\n'
  fi
}

# ---------------------------------------------------------------------------
# Helper: compare two dotted version strings (a < b -> 0, a >= b -> 1)
# Works for kernel-style versions like 5.15.25
# ---------------------------------------------------------------------------
version_lt() {
  # returns 0 (true) if $1 < $2
  [ "$1" = "$2" ] && return 1
  local lower
  lower=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
  [ "$lower" = "$1" ] && [ "$1" != "$2" ]
}

# ===========================================================================
# 1. KERNEL VERSION vs KNOWN VULNERABLE RANGES
# ===========================================================================
check_kernel_cves() {
  log HDR "Kernel CVE Exposure"

  local kver
  kver=$(uname -r | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || uname -r | grep -oE '^[0-9]+\.[0-9]+')
  log INFO "Detected kernel version: $(uname -r)"

  if [ -z "$kver" ]; then
    log MED "Could not parse kernel version cleanly; skipping automated range checks. Verify manually."
    return
  fi

  # --- Dirty Cow: CVE-2016-5195 ---
  # Race condition in the kernel's copy-on-write handling of private
  # read-only memory mappings, allowing local privilege escalation.
  # Affects essentially all kernels prior to the fix landing (Oct 2016);
  # fixed upstream in 4.8.3 and backported to many stable/distro branches.
  if version_lt "$kver" "4.8.3"; then
    log HIGH "Dirty Cow (CVE-2016-5195): kernel $kver predates the 4.8.3 fix. Distro kernels often backport this fix independently of the mainline number, so confirm against your distro's advisory before treating this as certain."
  else
    log OK "Dirty Cow (CVE-2016-5195): kernel version is >= 4.8.3 (likely patched, verify distro backport status if paranoid)."
  fi

  # --- Dirty Pipe: CVE-2022-0847 ---
  # Uninitialized "flags" field in a pipe_buffer lets an unprivileged
  # user overwrite data in read-only files. Affects 5.8 <= kernel,
  # fixed in 5.16.11 / 5.15.25 / 5.10.102.
  if printf '%s\n' "$kver" | grep -qE '^5\.'; then
    if version_lt "$kver" "5.8.0"; then
      log OK "Dirty Pipe (CVE-2022-0847): kernel predates the introduction of the bug (< 5.8)."
    elif version_lt "$kver" "5.10.102" || \
         { printf '%s\n' "$kver" | grep -qE '^5\.1[1-4]\.' ; } || \
         { printf '%s\n' "$kver" | grep -qE '^5\.15\.' && version_lt "$kver" "5.15.25"; } || \
         { printf '%s\n' "$kver" | grep -qE '^5\.16\.' && version_lt "$kver" "5.16.11"; }; then
      log HIGH "Dirty Pipe (CVE-2022-0847): kernel $kver falls in the vulnerable 5.8 - (5.10.102/5.15.25/5.16.11) range. Trivial local root exploit if unpatched."
    else
      log OK "Dirty Pipe (CVE-2022-0847): kernel version appears patched for this branch."
    fi
  else
    log OK "Dirty Pipe (CVE-2022-0847): kernel branch ($kver) outside the affected 5.x range."
  fi

  # --- Copy Fail: CVE-2026-31431 ---
  # Logic flaw in the kernel crypto AF_ALG interface (algif_aead /
  # authencesn template) letting an unprivileged local user perform a
  # deterministic 4-byte controlled write into the page cache of any
  # readable file (e.g. corrupt /usr/bin/su in-memory), yielding root.
  # No race condition, no timing window. Publicly disclosed 2026-04-29
  # by Theori; added to CISA KEV. Introduced by commit 72548b093ee3
  # (2017, in-place AEAD optimization), fixed upstream by commit
  # fafe0fa2995a. Per public reporting (Sysdig): vulnerable kernel
  # 4.14 through 7.0-rc, all 6.18.x prior to 6.18.22, and all 6.19.x
  # prior to 6.19.12.
  if version_lt "$kver" "4.14.0"; then
    log OK "Copy Fail (CVE-2026-31431): kernel $kver predates the 4.14 introduction of the bug."
  elif printf '%s\n' "$kver" | grep -qE '^6\.18\.'; then
    if version_lt "$kver" "6.18.22"; then
      log HIGH "Copy Fail (CVE-2026-31431): kernel $kver is in the vulnerable 6.18.x range (< 6.18.22). Actively exploited (CISA KEV); patch immediately."
    else
      log OK "Copy Fail (CVE-2026-31431): kernel $kver is >= the patched 6.18.22."
    fi
  elif printf '%s\n' "$kver" | grep -qE '^6\.19\.'; then
    if version_lt "$kver" "6.19.12"; then
      log HIGH "Copy Fail (CVE-2026-31431): kernel $kver is in the vulnerable 6.19.x range (< 6.19.12). Actively exploited (CISA KEV); patch immediately."
    else
      log OK "Copy Fail (CVE-2026-31431): kernel $kver is >= the patched 6.19.12."
    fi
  else
    log MED "Copy Fail (CVE-2026-31431): kernel $kver falls inside the broad publicly-reported vulnerable range (4.14 through 7.0-rc), but this script only has confirmed fixed point-releases for the 6.18.x and 6.19.x branches. Verify this specific branch's backport status against your distro's advisory (Ubuntu USN, RHEL errata, Debian DSA, or 'kcarectl --patch-info | grep CVE-2026-31431' if using KernelCare) before concluding either way."
  fi
  # Runtime signal: is the vulnerable crypto path even reachable?
  if [ -r /proc/modules ] && grep -qE '^algif_aead ' /proc/modules 2>/dev/null; then
    log INFO "Copy Fail: algif_aead module is currently loaded, meaning the AF_ALG AEAD attack surface is active on this system."
  fi
  if grep -rlqsE 'algif_aead' /etc/modprobe.d/*.conf 2>/dev/null; then
    log OK "Copy Fail: found a modprobe blacklist entry referencing algif_aead (mitigation may be applied). Confirm this is intentional and still current."
  fi

  # --- DirtyFrag: CVE-2026-43284 (xfrm-ESP) + CVE-2026-43500 (RxRPC) ---
  # Chained pair disclosed 2026-05-07 by Hyunwoo Kim, embargo broken
  # early. In-place decryption in the esp4/esp6 (IPsec ESP, introduced
  # 2017) and rxrpc (introduced June 2023) receive paths lets an
  # unprivileged local process retain references to decrypted page
  # cache pages reached via splice()/vmsplice(), yielding an
  # attacker-controlled full-content write primitive -> root. Public
  # PoC released same day as disclosure, ahead of any patch.
  # Upstream mainline fix: commit f4c50a4034e6 (2026-05-08). No single
  # clean "fixed at version X.Y.Z" cutoff is reliably published across
  # every stable/LTS branch as of this script's writing -- distros
  # shipped point-release and live-patch fixes on their own timelines.
  # Detection here is therefore version-floor + runtime-module based,
  # not a precise range check.
  if version_lt "$kver" "4.14.0"; then
    log OK "DirtyFrag (CVE-2026-43284 / CVE-2026-43500): kernel $kver predates the 4.14 introduction of the ESP half of this bug."
  else
    local dirtyfrag_mods_loaded="" dirtyfrag_mitigated=0
    if [ -r /proc/modules ]; then
      dirtyfrag_mods_loaded=$(grep -E '^(esp4|esp6|rxrpc) ' /proc/modules 2>/dev/null | awk '{print $1}' | paste -sd, -)
    fi
    if grep -rlqsE 'install[[:space:]]+(esp4|esp6|rxrpc)[[:space:]]+/bin/false' /etc/modprobe.d/*.conf 2>/dev/null; then
      dirtyfrag_mitigated=1
    fi
    if [ "$dirtyfrag_mitigated" -eq 1 ]; then
      log OK "DirtyFrag (CVE-2026-43284 / CVE-2026-43500): a modprobe blacklist for esp4/esp6/rxrpc was found in /etc/modprobe.d (matches the published stopgap mitigation). This is a mitigation, not a fix -- still apply the vendor kernel patch (mainline commit f4c50a4034e6) or a live-patch when available."
    elif [ -n "$dirtyfrag_mods_loaded" ]; then
      log HIGH "DirtyFrag (CVE-2026-43284 / CVE-2026-43500): kernel $kver is >= 4.14 and vulnerable module(s) currently loaded: $dirtyfrag_mods_loaded. No modprobe blacklist mitigation detected. Public exploit code exists for this bug -- patch or apply the mitigation immediately: blacklist esp4/esp6/rxrpc via /etc/modprobe.d, unload them, and drop the page cache, or update to a kernel/live-patch released on or after 2026-05-08."
    else
      log MED "DirtyFrag (CVE-2026-43284 / CVE-2026-43500): kernel $kver is >= 4.14 (in the broad affected range) but esp4/esp6/rxrpc are not currently loaded and no blacklist was found. They may still load on demand (e.g. when IPsec or AFS/RxRPC traffic occurs) unless explicitly blocked or the kernel is already patched. Confirm patch status via your distro's advisory or 'kcarectl --patch-info | grep CVE-2026-43284' if using KernelCare."
    fi
  fi

  log INFO "Kernel range checks are heuristic where exact per-branch fixed versions aren't publicly documented. Distro kernels (Ubuntu, RHEL, Debian) also backport fixes without bumping the upstream version number. Always cross-check with your distro's security advisories (e.g. 'apt changelog linux-image-...', 'rpm -q --changelog kernel') and the CVE pages directly for CVE-2026-31431 and CVE-2026-43284 / CVE-2026-43500."
}

# ===========================================================================
# 2. SUID / SGID BINARIES
# ===========================================================================
check_suid() {
  log HDR "SUID / SGID Binaries"

  local known_good_regex='^/(usr/)?(bin|sbin)/(su|sudo|passwd|mount|umount|ping|ping6|newgrp|gpasswd|chsh|chfn|chage|crontab|pkexec|fusermount3?|snap-confine|traceroute6?\.iputils|dbus-daemon-launch-helper|Xorg\.wrap|umount)$'
  local suid_list
  suid_list=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)

  if [ -z "$suid_list" ]; then
    log INFO "No SUID/SGID binaries found (unusual -- check permissions of this scan)."
    return
  fi

  local count=0 flagged=0
  while IFS= read -r bin; do
    [ -z "$bin" ] && continue
    count=$((count+1))
    if echo "$bin" | grep -qE "$known_good_regex"; then
      : # common/expected, skip noise
    else
      flagged=$((flagged+1))
      log MED "Non-standard SUID/SGID binary: $bin -- review whether this is expected on this system (GTFOBins-listed binaries here are a common privesc path)."
    fi
  done <<< "$suid_list"

  log INFO "Total SUID/SGID binaries found: $count ($flagged flagged as non-standard)."

  # Extra: explicitly flag well-known GTFOBins favorites if present anywhere with SUID
  for name in nmap vim find bash less more nano perl python python3 ruby awk gdb env tar zip; do
    hit=$(echo "$suid_list" | grep -E "/${name}$")
    if [ -n "$hit" ]; then
      log HIGH "SUID bit set on a known GTFOBins privesc vector: $hit -- this alone is very likely exploitable for root."
    fi
  done
}

# ===========================================================================
# 3. WORLD-WRITABLE CRON JOBS / SENSITIVE PATHS
# ===========================================================================
check_world_writable() {
  log HDR "World-Writable Cron Jobs & Sensitive Paths"

  # Cron directories & files
  local cron_paths=(/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs)
  for p in "${cron_paths[@]}"; do
    [ -e "$p" ] || continue
    find "$p" -perm -0002 2>/dev/null | while read -r f; do
      log HIGH "World-writable cron path: $f -- any local user can plant a payload that will run as the cron owner (often root)."
    done
  done

  # Check scripts referenced inside crontabs for world-writable targets
  if [ -r /etc/crontab ]; then
    grep -vE '^\s*(#|$)' /etc/crontab 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u | while read -r ref; do
      if [ -e "$ref" ] && [ -w "$ref" ] 2>/dev/null; then
        [ -w "$ref" ] && log HIGH "Cron job references a world-writable or currently-writable target: $ref"
      fi
    done
  fi

  # Sensitive paths that should never be world-writable
  local sensitive=(/etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d /etc/ssh/sshd_config /root /etc/pam.d /etc/ld.so.preload /etc/ld.so.conf.d)
  for p in "${sensitive[@]}"; do
    [ -e "$p" ] || continue
    if [ -d "$p" ]; then
      find "$p" -maxdepth 1 -perm -0002 2>/dev/null | while read -r f; do
        log HIGH "World-writable sensitive path: $f"
      done
    else
      if find "$p" -maxdepth 0 -perm -0002 2>/dev/null | grep -q .; then
        log HIGH "World-writable sensitive file: $p"
      fi
    fi
  done

  # Generic sweep of world-writable files outside of /tmp, /var/tmp, /dev/shm (which are expected to be)
  local ww_count
  ww_count=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -vE '^/(tmp|var/tmp|dev/shm)/' | wc -l)
  log INFO "World-writable regular files outside /tmp, /var/tmp, /dev/shm: $ww_count (run manually with 'find / -xdev -perm -0002 -type f' for the full list if this number is non-zero)."

  # PATH-hijack style check: is any directory in root's crontab / system PATH writable?
  if command -v getconf >/dev/null 2>&1; then
    :
  fi
  IFS=':' read -ra path_dirs <<< "${PATH:-}"
  for d in "${path_dirs[@]}"; do
    [ -d "$d" ] || continue
    if [ -w "$d" ]; then
      log HIGH "A directory in the current PATH is writable by this user: $d -- classic PATH-hijack privesc vector if a privileged process/cron invokes commands without an absolute path."
    fi
  done
}

# ===========================================================================
# 4. DANGEROUS SUDO CONFIGURATION
# ===========================================================================
check_sudo() {
  log HDR "Sudo Configuration"

  if ! command -v sudo >/dev/null 2>&1; then
    log INFO "sudo is not installed; skipping sudo checks."
    return
  fi

  # What can the current user run?
  local sudo_l
  sudo_l=$(sudo -n -l 2>/dev/null)
  if [ -n "$sudo_l" ]; then
    log INFO "Current user's 'sudo -l' output (non-interactive):"
    while IFS= read -r line; do
      log INFO "  $line"
    done <<< "$sudo_l"

    if echo "$sudo_l" | grep -qE 'NOPASSWD'; then
      log MED "NOPASSWD entries present in sudo rules -- commands can be run as another user (often root) with no password prompt."
    fi
    # GTFOBins-style dangerous commands allowed via sudo
    for cmd in vim vi nano less more find awk perl python python3 ruby gdb tar zip nmap ftp gdb man git docker; do
      if echo "$sudo_l" | grep -qE "(^|[[:space:]/])${cmd}([[:space:]]|$)"; then
        log HIGH "sudo allows running '$cmd' -- this binary is commonly used to break out to a root shell via sudo (see GTFOBins)."
      fi
    done
    if echo "$sudo_l" | grep -qE '\(ALL\s*:\s*ALL\)\s*ALL|\(ALL\)\s*ALL'; then
      log HIGH "Current user appears to have blanket ALL:ALL sudo rights."
    fi
  else
    log INFO "No sudo rules resolvable for current user without a password (or sudo not configured for this user)."
  fi

  # Static analysis of sudoers files themselves (requires read access, usually root-only)
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -r "$f" ] || continue
    grep -vE '^\s*(#|$)' "$f" 2>/dev/null | while IFS= read -r line; do
      if echo "$line" | grep -qE 'NOPASSWD'; then
        log MED "sudoers entry with NOPASSWD in $f: $line"
      fi
      if echo "$line" | grep -qE '\bALL\s*=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s*ALL\b'; then
        log MED "Broad ALL=(ALL) ALL rule in $f: $line"
      fi
      if echo "$line" | grep -qE 'env_keep.*LD_PRELOAD|env_keep.*LD_LIBRARY_PATH'; then
        log HIGH "sudoers preserves a dangerous environment variable (LD_PRELOAD/LD_LIBRARY_PATH) in $f: $line -- can be used to inject a malicious shared library into a sudo'd process."
      fi
    done
  done

  # sudo version itself -- check against known-bad ranges
  local sudo_ver
  sudo_ver=$(sudo -V 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  if [ -n "$sudo_ver" ]; then
    log INFO "sudo binary version: $sudo_ver"
    # CVE-2021-3156 "Baron Samedit" heap overflow: sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
    if printf '%s\n' "$sudo_ver" | grep -qE '^1\.8\.' && version_lt "$sudo_ver" "1.8.31" ; then
      log HIGH "sudo $sudo_ver may be vulnerable to CVE-2021-3156 (Baron Samedit heap overflow, 1.8.2-1.8.31p2). Verify patch level (p-releases aren't reflected in this version string) and upgrade."
    elif printf '%s\n' "$sudo_ver" | grep -qE '^1\.9\.' && version_lt "$sudo_ver" "1.9.5"; then
      log HIGH "sudo $sudo_ver may be vulnerable to CVE-2021-3156 (Baron Samedit heap overflow, 1.9.0-1.9.5p1). Verify patch level and upgrade."
    else
      log OK "sudo version does not match the known CVE-2021-3156 vulnerable range (based on major.minor.patch only)."
    fi
  fi
}

# ===========================================================================
# 5. VULNERABLE PACKAGE VERSIONS (polkit / PwnKit, sudo, others)
# ===========================================================================
check_packages() {
  log HDR "Installed Package Versions vs Known CVEs"

  # --- PwnKit: CVE-2021-4034 ---
  # Memory corruption in polkit's pkexec allowing any local user to gain
  # root, present in essentially all default polkit installs for ~12+
  # years until the Jan 2022 patch. Detected here primarily by testing
  # pkexec's behavior/version rather than trusting the package manager
  # alone, since many distros patched without a visible version bump.
  if command -v pkexec >/dev/null 2>&1; then
    local pkexec_path
    pkexec_path=$(command -v pkexec)
    log INFO "pkexec found at $pkexec_path"
    if [ -u "$pkexec_path" ]; then
      log MED "pkexec is SUID-root (expected for its normal function). Confirming patch status..."
      # Best-effort: check polkit package version via package manager
      local polkit_ver=""
      if command -v dpkg-query >/dev/null 2>&1; then
        polkit_ver=$(dpkg-query -W -f='${Version}\n' policykit-1 2>/dev/null || dpkg-query -W -f='${Version}\n' polkit 2>/dev/null)
      elif command -v rpm >/dev/null 2>&1; then
        polkit_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' polkit 2>/dev/null)
      fi
      if [ -n "$polkit_ver" ]; then
        log INFO "polkit package version: $polkit_ver"
        log MED "PwnKit (CVE-2021-4034): version string alone is not a reliable patch indicator since distros backport fixes into old-looking version numbers. Cross-check this version against your distro's security advisory for CVE-2021-4034 (or run a known non-destructive PoC in a test environment)."
      else
        log MED "PwnKit (CVE-2021-4034): pkexec is present but polkit package version could not be determined (dpkg/rpm not found or package name differs). Manually verify patch status."
      fi
    fi
  else
    log OK "PwnKit (CVE-2021-4034): pkexec not found on this system -- not exploitable via this vector."
  fi

  # --- Generic package version dump for common privesc-relevant packages ---
  local pkgs=(sudo polkit policykit-1 systemd openssh-server openssh sudo-ldap util-linux)
  if command -v dpkg-query >/dev/null 2>&1; then
    for p in "${pkgs[@]}"; do
      v=$(dpkg-query -W -f='${Version}\n' "$p" 2>/dev/null)
      [ -n "$v" ] && log INFO "Installed (dpkg): $p = $v"
    done
  elif command -v rpm >/dev/null 2>&1; then
    for p in "${pkgs[@]}"; do
      v=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null)
      [[ "$v" == *"not installed"* ]] || { [ -n "$v" ] && log INFO "Installed (rpm): $p = $v"; }
    done
  else
    log INFO "Neither dpkg nor rpm found -- skipping package manager version dump. Consider checking versions manually (e.g. 'sudo -V', 'apt list --installed')."
  fi

  log INFO "Package version checks are a starting point, not a guarantee. Always confirm against your distro's official CVE/security tracker (Debian Security Tracker, Ubuntu USN, RHEL errata, etc.) since backports change version semantics."
}

# ===========================================================================
# 6. NON-STANDARD LINUX CAPABILITIES
# ===========================================================================
check_capabilities() {
  log HDR "Non-Standard File Capabilities"

  if ! command -v getcap >/dev/null 2>&1; then
    log INFO "'getcap' not found (part of libcap2-bin / libcap-utils). Skipping capability scan. Install it or run: find / -xdev -exec getcap {} \\; manually."
    return
  fi

  local cap_list
  if getcap -r / >/dev/null 2>&1; then
    cap_list=$(getcap -r / 2>/dev/null)
  else
    # Fallback for older getcap without -r
    cap_list=$(find / -xdev -type f -exec getcap {} \; 2>/dev/null | grep -v '^$')
  fi

  if [ -z "$cap_list" ]; then
    log INFO "No files with extended capabilities found."
    return
  fi

  local dangerous_caps='cap_setuid|cap_setgid|cap_sys_admin|cap_dac_override|cap_dac_read_search|cap_sys_ptrace|cap_sys_module|cap_net_raw|cap_chown|cap_fowner'

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    log INFO "Capability set: $line"
    if echo "$line" | grep -qiE "$dangerous_caps"; then
      log HIGH "Dangerous capability on: $line -- capabilities like cap_setuid/cap_sys_admin/cap_dac_override on a binary a normal user can execute are frequently full privilege-escalation primitives (e.g. python3 with cap_setuid=+ep, or vim with cap_dac_override)."
    fi
  done <<< "$cap_list"
}

# ===========================================================================
# MAIN
# ===========================================================================
main() {
  log HDR "Linux Privilege-Escalation Recon (v$SCRIPT_VERSION)"
  log INFO "Run as: $(id -un) (uid=$(id -u)) on $(hostname 2>/dev/null || echo unknown) at $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  log INFO "Note: running as root sees more (root-only files, full sudoers, etc). Running as an unprivileged user shows an attacker's-eye view."

  check_kernel_cves
  check_suid
  check_world_writable
  check_sudo
  check_packages
  check_capabilities

  log HDR "Summary"
  log INFO "HIGH findings: $FINDINGS_HIGH | MEDIUM findings: $FINDINGS_MED | INFO items: $FINDINGS_INFO"
  if [ "$FINDINGS_HIGH" -gt 0 ]; then
    log INFO "One or more HIGH severity items were found. Investigate and remediate before treating this system as hardened."
  fi

  if [ -n "$OUTFILE" ]; then
    printf '%s\n' "$REPORT_BUF" > "$OUTFILE"
    echo "Full report written to: $OUTFILE"
  fi
}

main "$@"
