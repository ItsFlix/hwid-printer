#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static void hash_bytes(uint64_t *h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; ++i) {
        *h ^= (uint64_t)p[i];
        *h *= 1099511628211ULL; // FNV-1a 64-bit prime
    }
}

static void hash_string(uint64_t *h, const char *s) {
    if (!s) return;
    hash_bytes(h, s, strlen(s));
}

static BOOL read_reg_string(HKEY root, const char *subkey, const char *value_name, char *out, DWORD out_size) {
    HKEY hKey = NULL;
    DWORD type = 0;
    DWORD data_size = out_size;
    LONG r = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return FALSE;

    r = RegQueryValueExA(hKey, value_name, NULL, &type, (LPBYTE)out, &data_size);
    RegCloseKey(hKey);

    if (r != ERROR_SUCCESS) return FALSE;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return FALSE;

    out[out_size - 1] = '\0';
    return TRUE;
}

static void get_mac_addresses(uint64_t *hwid_hash) {
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = 0;
    DWORD dwRetVal = 0;

    // First call to get the size of the buffer
    if (GetAdaptersInfo(NULL, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
    }

    if (pAdapterInfo == NULL) {
        printf("MAC Address: <unable to allocate memory>\n");
        return;
    }

    // Second call to get the actual data
    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal != NO_ERROR) {
        printf("MAC Address: <unable to get adapter info>\n");
        free(pAdapterInfo);
        return;
    }

    pAdapter = pAdapterInfo;
    int adapter_count = 0;
    while (pAdapter) {
        // Only print physical adapters (not PPP, etc.)
        if (pAdapter->Type == MIB_IF_TYPE_ETHERNET) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X-%02X-%02X-%02X-%02X-%02X",
                pAdapter->Address[0],
                pAdapter->Address[1],
                pAdapter->Address[2],
                pAdapter->Address[3],
                pAdapter->Address[4],
                pAdapter->Address[5]);

            if (adapter_count == 0) {
                printf("MAC Address (Primary): %s\n", mac_str);
                // Hash the primary MAC address into HWID
                hash_bytes(hwid_hash, pAdapter->Address, 6);
            } else {
                printf("MAC Address (Adapter %d): %s\n", adapter_count, mac_str);
                // Hash additional adapters too
                hash_bytes(hwid_hash, pAdapter->Address, 6);
            }
            adapter_count++;
        }
        pAdapter = pAdapter->Next;
    }

    if (adapter_count == 0) {
        printf("MAC Address: <no physical adapters found>\n");
    }

    free(pAdapterInfo);
}

int main(void) {
    char cpu[256] = {0};
    char manuf[256] = {0};
    char product[256] = {0};
    char bios_ver[256] = {0};
    char sku[256] = {0};

    DWORD volume_serial = 0;
    uint64_t hwid = 14695981039346656037ULL; // FNV offset basis

    // 1) Get the system drive volume serial
    if (!GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, NULL, NULL, NULL, 0)) {
        fprintf(stderr, "GetVolumeInformation failed: %lu\n", GetLastError());
        return 1;
    }

    // 2) Read hardware info from the registry
    read_reg_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "ProcessorNameString", cpu, sizeof(cpu));

    read_reg_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SystemManufacturer", manuf, sizeof(manuf));

    read_reg_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SystemProductName", product, sizeof(product));

    read_reg_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BIOSVersion", bios_ver, sizeof(bios_ver));

    read_reg_string(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SystemSKU", sku, sizeof(sku));

    // 3) Mix in the data to build a pseudo-HWID
    hash_string(&hwid, cpu);
    hash_string(&hwid, manuf);
    hash_string(&hwid, product);
    hash_string(&hwid, bios_ver);
    hash_string(&hwid, sku);

    char serial_buf[32];
    snprintf(serial_buf, sizeof(serial_buf), "%08X", volume_serial);
    hash_string(&hwid, serial_buf);

    printf("=== System Hardware Identification ===\n");
    printf("CPU: %s\n", cpu[0] ? cpu : "<unknown>");
    printf("Manufacturer: %s\n", manuf[0] ? manuf : "<unknown>");
    printf("Product: %s\n", product[0] ? product : "<unknown>");
    printf("BIOS: %s\n", bios_ver[0] ? bios_ver : "<unknown>");
    printf("Volume Serial: %s\n", serial_buf);

    // 4) Get MAC addresses
    printf("\n=== Network Adapters ===\n");
    get_mac_addresses(&hwid);

    printf("\n=== Final HWID ===\n");
    printf("HWID: %016llX\n", (unsigned long long)hwid);

    return 0;
}
