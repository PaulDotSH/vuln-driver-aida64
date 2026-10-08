# vuln-driver-aida64

DISCLAIMER: This repository contains ai assisted code and documentation, however everything was manually verified

Arbitrary physical memory read/write (and MSR read/write) via the AIDA64
kernel driver, exploitable from an unprivileged, non-admin user process.

The driver's device object (`\Device\AIDA64Driver`) is created with no ACL
restrictions, so any process that can reach it can issue IOCTLs that read or
write arbitrary physical memory, read/write MSRs, and access port I/O / PCI
configuration space.

## Affected files

| File | SHA-256 | Size |
|---|---|---|
| `aida64.sys` | `27375351b4a723465f937866f0ffc86e8e612b093673ee25ccf0b7ea803f888f` | 34,648 bytes |
| `aida64x.sys` (`kerneld.x64`) | `eba3233869c744271d5c22e4c1011ce866987d444a00bb78e4089637b7ed794b` | 68,376 bytes |

Both binaries are included in this repo for reproducibility/analysis.

## Vulnerable IOCTLs

| IOCTL | Effect |
|---|---|
| `0x80112074` | Read 4 bytes from physical address `(hi<<32)\|lo` |
| `0x80112078` | Write 4 bytes to physical address `(hi<<32)\|lo` |
| `0x80112040` | `memcpy(dest_va, MmMapIoSpace(phys, size), size)` — bulk physical read into a user-supplied VA |
| `0x8011204c` / `0x80112084` | `rdmsr` / `wrmsr` |

The driver also exposes port I/O and PCI configuration space read/write
handlers. No caller-context or privilege check is performed before any of
these operations.

## PoC

[`aida64_rw.c`](aida64_rw.c) is a **self-verifying** proof of concept. It
does not take an address on the command line and does not hand you a ready
"poke anything" tool, this is done intentionally intentionally. What it does instead:

1. Opens `\Device\AIDA64Driver`.
2. Allocates a large tagged buffer in its own user-mode process and fills it
   with a unique marker.
3. Uses the driver's bulk physical-read IOCTL to scan physical memory and
   locate that marker, proving arbitrary physical memory read.
4. Reads the located physical address back through the single-dword read
   IOCTL and confirms it matches.
5. Writes a new value to that physical address through the driver, and
   confirms the change is visible in its own user-mode buffer — proving
   arbitrary physical memory **write**, not just read.
6. Restores the original value before exiting.

I deliberately left the exact exploitation setup (how you turn "arbitrary
phys R/W" into, say, full kernel code execution or an AV/EDR kill primitive)
out of this write-up and out of the PoC. The point of this repo is to
document and verify the vulnerability for the advisory/vendor process, not
to hand out a drop-in weaponized tool. I also have a working
[memflow](https://github.com/memflow/memflow) connector built on top of this
driver (full virtual-memory access to the running OS from an unprivileged
process), which I'm **not** publishing, for the same reason.

## Disclosure status

- Report:
  [magicsword-io/LOLDrivers#461](https://github.com/magicsword-io/LOLDrivers/issues/461).
- This has been reported to MITRE for a CVE/advisory update, referencing the
  LOLDrivers PR above:
  [GHSA-xp8w-jxfc-xrqq](https://github.com/advisories/GHSA-xp8w-jxfc-xrqq).

