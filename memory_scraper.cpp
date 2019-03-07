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
        proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
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
        printf("Found string at: %x\n", it);
        printf("String: %s\n", it);
      }
    }
    free(lpbuffer);
  }
}

