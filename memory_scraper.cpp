#include <vector>
#include <algorithm>
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

int main() {
  HANDLE proc;

  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (Process32First(snapshot, &entry) == TRUE) {
    while (Process32Next(snapshot, &entry) == TRUE) {
      if (strcmp(entry.szExeFile, "a.exe") == 0) {
        proc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
        break;
      }
    }
  }

  if (proc == NULL) {
    std::cout << "Open process failed" << std::endl;
  }

  SYSTEM_INFO lpsysteminfo;

  GetSystemInfo(&lpsysteminfo);

  MEMORY_BASIC_INFORMATION info;
  SIZE_T bytesread;

  char tofind[19] = "You can't";
  char hacked[20] = "GET HACKED";
  int len = strlen(tofind);
  void* it;

  for(void* addr = lpsysteminfo.lpMinimumApplicationAddress; VirtualQueryEx(proc, addr, &info, sizeof(info)) == sizeof(info); addr += info.RegionSize) {
    printf("Base address: %x\n", info.BaseAddress);
    void* lpbuffer = malloc(info.RegionSize);
    bool res = ReadProcessMemory(proc, info.BaseAddress, lpbuffer, info.RegionSize, &bytesread);
    printf("Bytes read: %x\n", bytesread);
    if (bytesread) {
      it = (void*) std::search((char*) lpbuffer, (char*) lpbuffer + bytesread, tofind, tofind + len);
      if (it != lpbuffer + bytesread) {
        printf("Offset: %x\n", (long long)it - (long long)lpbuffer);
        DWORD oldprotect;
        //res = VirtualProtectEx(proc, info.BaseAddress, bytesread, 0x4, &oldprotect);
        if (!res) {
          std::cout << "Virtualprotect failed" << std::endl;
        }
        printf("Found string at: %x\n", it);
        printf("String: %s\n", it);
        SIZE_T bytes_written = 0;
        res = WriteProcessMemory(proc, (void*)((long long)info.BaseAddress + (long long)it - (long long)lpbuffer), hacked, strlen(hacked), &bytes_written);
        if (!res) {
          LPTSTR pTmp = NULL;
          DWORD errnum = GetLastError();
          FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ARGUMENT_ARRAY,
                NULL, 
                errnum, 
                LANG_NEUTRAL,
                (LPTSTR)&pTmp, 
                0,
                NULL
                );
          std::cout << pTmp << std::endl;
        }
        printf("Bytes injected: %d\n", bytes_written);
        exit(0);
      }
    }
    free(lpbuffer);
  }
}

