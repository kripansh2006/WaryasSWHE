/*
Rop using WNDPROC hook
  */

#include <windows.h> 
#include <stdio.h>
#include <psapi.h>
#include <shlobj.h> 
#pragma comment(lib, "ntdll.lib")

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // q: UNICODE_STRING
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_SECTION_NAME
{
    UNICODE_STRING SectionFileName;
    WCHAR NameBuffer[ANYSIZE_ARRAY];
} MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

extern "C" NTSTATUS NTAPI NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);


class TargetProcess {
private:
    HWND t_hwnd;
    DWORD t_pid;
    DWORD t_tid;
public:
    TargetProcess() {
        t_hwnd = FindWindowW(L"Respawn001", L"Apex Legends");
        if (!t_hwnd)
            return;
        t_tid = GetWindowThreadProcessId(t_hwnd, &t_pid);
        return;
    }
    
    bool IsReady() {
        return (t_hwnd && t_pid && t_tid);
    }

    auto get_pid() const {
        return t_pid;
    }
    auto get_tid() const {
        return t_tid;
    }
    auto get_hwnd() const {
        return t_hwnd;
    }

};


class ExploitMem {
public:
    inline static uintptr_t local_shared_memory = 0;
    inline static uintptr_t remote_shared_memory = 0;
    inline static char shared_count = 0;

    static void Init() {
        char path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, SHGFP_TYPE_CURRENT, path);
        if (*path != 0)
            ExploitMem::local_shared_memory = 0;
    }

    static bool find_local_memory() {
        MEMORY_BASIC_INFORMATION mbi{};
        char* pAddress = nullptr;

        while (true) {
            if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            if (isValidRegion(mbi)) {
                PSAPI_WORKING_SET_EX_INFORMATION wsInfo{};
                wsInfo.VirtualAddress = mbi.BaseAddress;
                QueryWorkingSetEx(GetCurrentProcess(), &wsInfo, sizeof(wsInfo));
                shared_count = wsInfo.VirtualAttributes.ShareCount;
                local_shared_memory = (uintptr_t)mbi.BaseAddress;
                return true;
            }

            pAddress += mbi.RegionSize;
        }
        return false;
    }

    static bool find_remote_memory(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (!hProcess) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        char* pAddress = nullptr;

        while (true) {
            SIZE_T return_len{};
            NtQueryVirtualMemory(hProcess, pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), &return_len);
            if (return_len == 0) {
                break;
            }

            if (isValidRegion(mbi)) {
                PSAPI_WORKING_SET_EX_INFORMATION wsInfo{};
                wsInfo.VirtualAddress = mbi.BaseAddress;
                QueryWorkingSetEx(hProcess, &wsInfo, sizeof(wsInfo));
                if (shared_count == wsInfo.VirtualAttributes.ShareCount) {
                    remote_shared_memory = (uintptr_t)pAddress;
                    CloseHandle(hProcess);
                    return true;
                }
            }

            pAddress += mbi.RegionSize;
        }

        CloseHandle(hProcess);
        return false;
    }

private:
    static bool isValidRegion(const MEMORY_BASIC_INFORMATION& mbi) {
        return mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize == 4096 && mbi.Type == MEM_MAPPED;
    }
};


class Exploit {
private:
    void* gadget_pop_rcx_ret{};
    void* gadget_pop_rdx_ret{};
    void* gadget_pop_rax_ret{};
    void* gadget_mov_ptr_rcx_rdx_ret{};
    void* gadget_mov_ptr_rdx_rcx_ret{};
    void* gadget_deref_rcx_rax{};
    void* gadget_align_stack{};
    void* gadget_swap_stack{};
    void* gadget_write_rax_to_rcx_ptr{};
    void* gadget_add_rbp_to_rax{};
    void* gadget_push_rax_pop_rsp{};

    unsigned long long sh_ptr = 0;

    static void* FindSignature(HMODULE dll, const unsigned char* buffer, size_t size) {
        if (dll == nullptr || buffer == nullptr || size == 0) {
            return nullptr;
        }

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), dll, &modInfo, sizeof(MODULEINFO))) {
            return nullptr;
        }

        auto base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        auto maxAddress = base + modInfo.SizeOfImage;
        MEMORY_BASIC_INFORMATION mbi;

        while (base < maxAddress && VirtualQuery(base, &mbi, sizeof(mbi))) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & PAGE_EXECUTE_READ)) {
                auto checkLimit = min(static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize, maxAddress);
                auto end = checkLimit - size;

                for (auto current = static_cast<BYTE*>(mbi.BaseAddress); current <= end; ++current) {
                    if (memcmp(current, buffer, size) == 0) {
                        return current;
                    }
                }
            }

            base = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return nullptr;
    }

    void* FindGadget(const char* dllName, const unsigned char* signature, size_t size) {
        HMODULE dll = LoadLibraryA(dllName);
        if (!dll)
            return 0;
        return FindSignature(dll, signature, size);
    }

public:
    Exploit() {
        // Gadgets signatures
        unsigned char sig_pop_rcx_ret[] = "\x59\xC3";
        unsigned char sig_pop_rdx_ret[] = "\x5A\xC3";
        unsigned char sig_pop_rax_ret[] = "\x58\xC3";
        unsigned char sig_mov_ptr_rcx_rdx_ret[] = "\x48\x89\x11\xC3";
        unsigned char sig_mov_ptr_rdx_rcx_ret[] = "\x48\x89\x0A\xC3";
        unsigned char sig_deref_rcx_rax[] = "\x48\x8B\x01\xC3";
        unsigned char sig_write_rax_to_rcx_ptr[] = "\x48\x89\x01\xC3";
        unsigned char signature_gadget_align_stack[] = "\x48\x81\xC4\xE8\x00\x00\x00\xC3";
        unsigned char signature_gadget_swap_stack[] = "\x5C\xC3";
        unsigned char sig_add_rbp_to_rax[] = "\x48\x01\xE8\xC3";
        unsigned char sig_push_rax_pop_rsp[] = "\x50\x5c\xC3";

        // Search order: ntdll, kernel32, user32
        const char* dlls[] = { "ntdll.dll", "kernel32.dll", "user32.dll", "ws2_32.dll", "shell32.dll", "dxgi.dll", "crypt32.dll", "advapi32.dll", "ole32.dll", "secur32.dll", "psapi.dll", "rasadhlp.dll", "msctf.dll", "ntasn1.dll", "SHCore.dll", "avifil32.dll", "cryptsp.dll", "wbemsvc.dll", "winmmbase.dll", "MpOAV.dll", "combase.dll", "dwmapi.dll", "powrprof.dll", "ncrypt.dll", "MMDevAPI.dll", "msvcp_win.dll", "propsys.dll", "CoreMessaging.dll", "cryptbase.dll", "IPHLPAPI.DLL", "drvstore.dll", "gdi32full.dll", "version.dll",  "midimap.dll", "coloradapterclient.dll", "wininet.dll", "Windows.UI.dll", "cryptnet.dll", "wbemcomn.dll", "bcrypt.dll", "mscms.dll", "schannel.dll", "userenv.dll", "amsi.dll", "rsaenh.dll", "ucrtbase.dll", "msvfw32.dll", "d3d11.dll", "devobj.dll", "dhcpcsvc6.dll", "wintrust.dll", "xinput1_3.dll", "mswsock.dll", "wdmaud.drv", "sxs.dll", "bcryptprimitives.dll", "ncryptsslp.dll", "gdi32.dll", "normaliz.dll", "clbcatq.dll", "fastprox.dll", "profapi.dll", "win32u.dll", "avrt.dll", "NapiNSP.dll", "WinTypes.dll", "pnrpnsp.dll", "CoreUIComponents.dll", "D3DCompiler_43.dll", "umpdc.dll", "XAudio2_9.dll", "KernelBase.dll", "ntmarta.dll", "sspicli.dll", "kernel.appcore.dll", "steamclient64.dll", "dhcpcsvc.dll", "ksuser.dll", "InputHost.dll", "msvcrt.dll", "imm32.dll", "AudioSes.dll", "dnsapi.dll", "wshbth.dll", "cfgmgr32.dll", "mskeyprotect.dll", "msacm32.dll", "twinapi.appcore.dll", "wbemprox.dll", "oleaut32.dll", "msasn1.dll", "winrnr.dll", "hid.dll", "setupapi.dll", "dsound.dll", "windows.storage.dll", "dbghelp.dll", "WindowManagementAPI.dll", "vstdlib_s64.dll", "nlaapi.dll", "ResourcePolicyClient.dll", "comctl32.dll", "msacm32.drv", "dbgcore.dll", "imagehlp.dll", "rpcrt4.dll", "FWPUCLNT.DLL", "DXCore.dll", "uxtheme.dll", "TextInputFramework.dll", "winmm.dll", "Windows.Internal.Graphics.Display.DisplayColorManagement.dll", "Wldap32.dll", "shlwapi.dll", "wldp.dll", "sechost.dll", "nsi.dll" };
        for (const char* dll : dlls) {
            if (!gadget_pop_rcx_ret)
                gadget_pop_rcx_ret = FindGadget(dll, sig_pop_rcx_ret, sizeof(sig_pop_rcx_ret) - 1);
            if (!gadget_pop_rax_ret)
                gadget_pop_rax_ret = FindGadget(dll, sig_pop_rax_ret, sizeof(sig_pop_rax_ret) - 1);

            if (!gadget_pop_rdx_ret)
                gadget_pop_rdx_ret = FindGadget(dll, sig_pop_rdx_ret, sizeof(sig_pop_rdx_ret) - 1);
            if (!gadget_mov_ptr_rcx_rdx_ret)
                gadget_mov_ptr_rcx_rdx_ret = FindGadget(dll, sig_mov_ptr_rcx_rdx_ret, sizeof(sig_mov_ptr_rcx_rdx_ret) - 1);
            if (!gadget_mov_ptr_rdx_rcx_ret)
                gadget_mov_ptr_rdx_rcx_ret = FindGadget(dll, sig_mov_ptr_rdx_rcx_ret, sizeof(sig_mov_ptr_rdx_rcx_ret) - 1);
            if (!gadget_deref_rcx_rax)
                gadget_deref_rcx_rax = FindGadget(dll, sig_deref_rcx_rax, sizeof(sig_deref_rcx_rax) - 1);

            if (!gadget_write_rax_to_rcx_ptr)
                gadget_write_rax_to_rcx_ptr = FindGadget(dll, sig_write_rax_to_rcx_ptr, sizeof(sig_write_rax_to_rcx_ptr) - 1);
            if (!gadget_align_stack)
                gadget_align_stack = FindGadget(dll, signature_gadget_align_stack, sizeof(signature_gadget_align_stack) - 1);
            if (!gadget_swap_stack)
                gadget_swap_stack = FindGadget(dll, signature_gadget_swap_stack, sizeof(signature_gadget_swap_stack) - 1);
            if (!gadget_add_rbp_to_rax)
                gadget_add_rbp_to_rax = FindGadget(dll, sig_add_rbp_to_rax, sizeof(sig_add_rbp_to_rax) - 1);

            if (!gadget_push_rax_pop_rsp)
                gadget_push_rax_pop_rsp = FindGadget(dll, sig_push_rax_pop_rsp, sizeof(sig_push_rax_pop_rsp) - 1);

            if (gadget_pop_rcx_ret && gadget_pop_rdx_ret && gadget_pop_rax_ret && gadget_mov_ptr_rcx_rdx_ret && gadget_mov_ptr_rdx_rcx_ret &&
                gadget_align_stack && gadget_swap_stack && gadget_deref_rcx_rax && gadget_write_rax_to_rcx_ptr &&
                gadget_add_rbp_to_rax && gadget_push_rax_pop_rsp)
                break;  // Exit if all gadgets are found
        }
    }

    bool IsReady() {
        return (gadget_pop_rcx_ret && gadget_pop_rdx_ret && gadget_pop_rax_ret && gadget_mov_ptr_rcx_rdx_ret && gadget_mov_ptr_rdx_rcx_ret &&
            gadget_align_stack && gadget_swap_stack && gadget_deref_rcx_rax && gadget_write_rax_to_rcx_ptr &&
            gadget_add_rbp_to_rax && gadget_push_rax_pop_rsp);
    }

    void set_rax(unsigned long long val) {
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_pop_rax_ret;
        sh_ptr += sizeof(void*);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = val;
        sh_ptr += sizeof(void*);
    }

    void set_rcx(unsigned long long val) {
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_pop_rcx_ret;
        sh_ptr += sizeof(void*);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = val;
        sh_ptr += sizeof(void*);
    }

    void set_rdx(unsigned long long val) {
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_pop_rdx_ret;
        sh_ptr += sizeof(void*);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = val;
        sh_ptr += sizeof(void*);
    }

    void fix_stack_and_return() {
        set_rax(-0x80);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_add_rbp_to_rax;
        sh_ptr += sizeof(void*);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_push_rax_pop_rsp;
        sh_ptr += sizeof(void*);
    }

    unsigned long long read_memory(TargetProcess& target, unsigned long long ptr_to_read) {
#define STACK_OFFSET 0x800
#define READ_MEM 0x800 - sizeof(void*)
        sh_ptr = STACK_OFFSET;

        set_rcx(ptr_to_read);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_deref_rcx_rax;
        sh_ptr += sizeof(void*);
        set_rcx(ExploitMem::remote_shared_memory + READ_MEM);
        *(unsigned long long*)(ExploitMem::local_shared_memory + sh_ptr) = (unsigned long long)gadget_write_rax_to_rcx_ptr;
        sh_ptr += sizeof(void*);
        fix_stack_and_return();


        ShowWindow(target.get_hwnd(), 0);
        auto hhook = SetWindowsHookExA(WH_CALLWNDPROC, (HOOKPROC)gadget_align_stack, LoadLibraryA("ws2_32.dll"), target.get_tid());
        SendMessageA(target.get_hwnd(), WM_MOUSEACTIVATE, ExploitMem::remote_shared_memory + STACK_OFFSET, (LPARAM)gadget_swap_stack);
        UnhookWindowsHookEx(hhook);
        UnhookWindowsHookEx(hhook);
        ShowWindow(target.get_hwnd(), 1);

        printf("Read : %llx\n", *(unsigned long long*)(ExploitMem::local_shared_memory + READ_MEM));

        return 0;
    }
};

int main() {


    


    auto target = TargetProcess();



    auto exploit = Exploit();

    if (!exploit.IsReady()) {
        printf("Fail\n");
        return -1;
    }
   

   ExploitMem::Init();

    if (!ExploitMem::find_local_memory()) {
        printf("Didn't work\n");
        return -1;
    }
    
    
    if (!target.IsReady()) {
        printf("Apex not open\n");
        return -1;
    }

    if (!ExploitMem::find_remote_memory(target.get_pid())) {
        printf("No Remote\n");
    }

    memset((void*)ExploitMem::local_shared_memory, 0, 0x1000);
    exploit.read_memory(target, 0x7ffe0000);
	return 0;
}
