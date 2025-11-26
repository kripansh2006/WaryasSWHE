#include "internal-hook.hpp"
#include <cinttypes>
#include <dxgi1_6.h>
#include <d3d12.h>
#include <d3d11_4.h>
#include <unordered_map>
#include "hde/mhde_wrapper.hpp"

#include "ex/exploit.hpp"




struct FrameContext {
    ID3D12CommandAllocator* allocator = nullptr;
    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle{};
    ID3D12Resource* backbuffer = nullptr;
};

struct Vertex { float x, y, z, u, v; };

struct original_prologue {
    uint64_t len;
    uint8_t bytes[32];
};

struct present_ipc
{
    volatile bool lock = false;
    volatile bool active = false;
    volatile uint64_t func = 0;
    volatile uint64_t arg[8]{};
    IDXGISwapChain* swapchain = 0;
    ID3D12CommandQueue* queue = 0;
    volatile uint64_t spoofhelper = 0;
    volatile uint64_t rbx = 0;
    volatile uint64_t r14 = 0;
    volatile uint64_t result = 0;
    volatile bool virtualfunc = false;
    volatile uint16_t index = false;
    volatile uint64_t rdx = 0;
    volatile uint64_t r8 = 0;
    volatile uint64_t prologue16b = 0;
    original_prologue orig_prologue{};
};
struct SyncBackEntry {
    void* dst;
    size_t size;
    size_t offset;
};




template <typename T>
struct function_traits;

template <typename R, typename... Params>
struct function_traits<R(*)(Params...)> {
    using return_type = R;
    using argument_types = std::tuple<Params...>;
};

template <typename R, typename C, typename... Params>
struct function_traits<R(C::*)(Params...)> {
    using return_type = R;
    using argument_types = std::tuple<C*, Params...>;
};

template <typename R, typename C, typename... Params>
struct function_traits<R(C::*)(Params...) const> {
    using return_type = R;
    using argument_types = std::tuple<const C*, Params...>;
};

present_ipc* p_ipc = 0;

template <typename Tuple, typename... Args>
constexpr bool tuple_convertible() {
    if constexpr (sizeof...(Args) != std::tuple_size_v<Tuple>) {
        return false;
    }
    else {
        return ([]<std::size_t... I>(std::index_sequence<I...>) {
            return (std::is_convertible_v<Args, std::tuple_element_t<I, Tuple>> && ...);
        })(std::make_index_sequence<std::tuple_size_v<Tuple>>{});
    }
}


template <typename T>
constexpr uint64_t to_u64(T&& value) {
    if constexpr (std::is_integral_v<std::decay_t<T>> && sizeof(T) <= sizeof(uint64_t)) {
        return static_cast<uint64_t>(value);
    }
    else {
        return reinterpret_cast<uint64_t>(value);
    }
}

static inline void set_original_prologue(const uint8_t* p)
{
    static std::unordered_map<const void*, original_prologue> cache;

    if (auto it = cache.find(p); it != cache.end())
    {
        p_ipc->func += it->second.len;
        p_ipc->orig_prologue = it->second;

        return;
    }

    cache[p] = {};
    CMHDE mhde;
    auto len = mhde.Disassemble(p);
    while (len < 14)
        len += mhde.Disassemble(p + len);

    cache[p].len = len;
    memcpy(cache[p].bytes, p, len);
    *(uint32_t*)&cache[p].bytes[len] = 0x862ff41;


    p_ipc->func += len;
    p_ipc->orig_prologue = cache[p];

    return;
}

// Displacement finder with caching
static inline uint64_t find_valid_disp_cached(const uint8_t* p)
{
    static std::unordered_map<const void*, uint64_t> cache;

    if (auto it = cache.find(p); it != cache.end())
    {
        return it->second;
    }

    for (size_t i = 0; i < 30; ++i)
    {
        //mov rax,QWORD PTR [rax+?32]
        if (i + 6 < 30 && p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x80)
        {
            int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
            if (disp > 0 && disp % 8 == 0)
            {
                cache[p] = static_cast<uint64_t>(disp);
                return disp;
            }
        }
        //mov rax,QWORD PTR [rax+?]
        if (i + 3 < 30 && p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x40)
        {
            int8_t disp = static_cast<int8_t>(p[i + 3]);
            if (disp > 0 && disp % 8 == 0)
            {
                cache[p] = static_cast<uint64_t>(disp);
                return disp;
            }
        }
        //jmp qword ptr [rax+?]
        if (i + 3 < 30 && p[i] == 0xFF && p[i + 1] == 0x60)
        {
            int8_t disp = static_cast<int8_t>(p[i + 2]);
            if (disp > 0 && disp % 8 == 0)
            {
                cache[p] = static_cast<uint64_t>(disp);
                return disp;
            }
        }
        //jmp qword ptr [rax+?32]
        if (i + 6 < 30 && p[i] == 0xFF && p[i + 1] == 0xA0)
        {
            int32_t disp = *reinterpret_cast<const int32_t*>(&p[i + 2]);
            if (disp > 0 && disp % 8 == 0)
            {
                cache[p] = static_cast<uint64_t>(disp);
                return disp;
            }
        }
    }

    cache[p] = 0;
    return 0;
}


template<typename Func, typename... Args>
uint64_t ipc_call(CExploit& ex, Func fn, Args&&... args)
{

    static_assert(sizeof...(Args) <= 8, "Too many arguments");

    using Return = typename function_traits<Func>::return_type;
    constexpr bool is_struct_return =
        std::is_class_v<Return> &&
        std::is_trivially_copyable_v<Return> &&
        !std::is_void_v<Return> &&
        !std::is_integral_v<Return>;

    // If a struct is returned, enforce that the last argument is Return*
    if constexpr (is_struct_return) {
        static_assert(sizeof...(Args) >= 1, "Missing struct return output pointer");
        using LastArg = std::tuple_element_t<sizeof...(Args) - 1, std::tuple<std::decay_t<Args>...>>;
        static_assert(std::is_pointer_v<LastArg>, "Last argument must be a pointer to struct return type");
        static_assert(std::is_same_v<std::remove_cv_t<std::remove_pointer_t<LastArg>>, Return>,
            "Last argument must be a pointer to the return type struct");
    }

    static std::vector<SyncBackEntry> sync_entries;
    sync_entries.clear();
    size_t cursor = 0;

    if constexpr (std::is_member_function_pointer_v<Func>) {
        using expected_args = typename function_traits<Func>::argument_types;
        if constexpr (!is_struct_return) {
            static_assert(tuple_convertible<expected_args, Args...>(),
                "ipc_call: arguments not convertible to member function signature");
        }
        static_assert(sizeof(fn) <= sizeof(uint64_t), "Member function pointer too large");

        p_ipc->func = 0;
        p_ipc->virtualfunc = 1;
        auto b = *reinterpret_cast<const uint64_t*>(&fn);
        p_ipc->index = find_valid_disp_cached(reinterpret_cast<const uint8_t*>(b));
    }
    else if constexpr (std::is_pointer_v<Func>) {
        using expected_args = typename function_traits<Func>::argument_types;
        static_assert(tuple_convertible<expected_args, Args...>(),
            "ipc_call: arguments not convertible to function signature");

        p_ipc->virtualfunc = 0;
        p_ipc->func = std::bit_cast<uint64_t>(fn);
    }
    else {
        static_assert([] { return false; }(), "Unsupported function type in ipc_call");
    }

    uint64_t* dest = const_cast<uint64_t*>(p_ipc->arg);
    size_t i = 0;

    auto process_arg = [&](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_pointer_v<T>) {
            using Pointee = std::remove_pointer_t<T>;

            if constexpr (std::is_trivially_copyable_v<Pointee>) {
                size_t size = 0;
                if constexpr (std::is_same_v<Pointee, char> || std::is_same_v<Pointee, const char>) {
                    size = std::strlen(arg) + 1;
                }
                else if constexpr (std::is_same_v<Pointee, wchar_t> || std::is_same_v<Pointee, const wchar_t>) {
                    size = (std::wcslen(arg) + 1) * sizeof(wchar_t);
                }
                else if constexpr (std::is_same_v<Pointee, Vertex>) {
                    size = sizeof(Vertex) * 4;
                }
                else if constexpr (std::is_same_v<Pointee, D3D11_INPUT_ELEMENT_DESC>) {
                    size = sizeof(D3D11_INPUT_ELEMENT_DESC) * 2;
                }
                else {
                    size = sizeof(Pointee);
                }


                uint8_t* local_base = reinterpret_cast<uint8_t*>(ex.get_LocalSharedMemory()) + PAD_DATA + cursor;
                uint8_t* remote_base = reinterpret_cast<uint8_t*>(ex.get_RemoteSharedMemory()) + PAD_DATA + cursor;

                std::memcpy(local_base, arg, size);
                dest[i++] = reinterpret_cast<uint64_t>(remote_base);

                if constexpr (!std::is_const_v<Pointee>) {
                    sync_entries.push_back(SyncBackEntry{
                        const_cast<void*>(static_cast<const void*>(arg)), size, cursor
                        });
                }

                cursor += size;
            }
            else {
                dest[i++] = reinterpret_cast<uint64_t>(arg); // non-trivial, pass raw pointer
            }
        }
        else if constexpr (std::is_lvalue_reference_v<decltype(arg)> && std::is_trivially_copyable_v<T>) {
            size_t size = sizeof(T);

            if constexpr (sizeof(T) <= 8) {
                auto dst = &dest[i++];
                std::memset(dst, 0, 8);
                std::memcpy(dst, &arg, 8);
            }
            else {
                uint8_t* local_base = reinterpret_cast<uint8_t*>(ex.get_LocalSharedMemory()) + PAD_DATA + cursor;
                uint8_t* remote_base = reinterpret_cast<uint8_t*>(ex.get_RemoteSharedMemory()) + PAD_DATA + cursor;

                std::memcpy(local_base, &arg, size);
                dest[i++] = reinterpret_cast<uint64_t>(remote_base);

                cursor += size;
            }
        }
        else {
            if constexpr (sizeof(std::forward<decltype(arg)>(arg)) <= 8) {
                auto dst = &dest[i++];
                std::memset(dst, 0, 8);
                std::memcpy(dst, &arg, 8);
            }
            else {
                dest[i++] = (uint64_t)(std::forward<decltype(arg)>(arg));
            }
        }
        };

    (process_arg(std::forward<Args>(args)), ...);
    p_ipc->prologue16b = 0;
    p_ipc->active = 1;

    while (!p_ipc->prologue16b)
    {
        _mm_pause();
    }

    if (*(uint16_t*)(p_ipc->func) != p_ipc->prologue16b)
    {
        printf("Hook detected at 0x%llx, jitting it\n", p_ipc->func);
        set_original_prologue((uint8_t*)p_ipc->func);
        p_ipc->prologue16b = 0xB00B;
    }
    else {
        p_ipc->prologue16b = 0xDEAD;
    }


    while (p_ipc->active) {
        _mm_pause();
    }
    for (const auto& entry : sync_entries) {
        void* src = reinterpret_cast<uint8_t*>(ex.get_LocalSharedMemory()) + PAD_DATA + entry.offset;
        std::memcpy(entry.dst, src, entry.size);
    }

    return p_ipc->result;
}



uint32_t GetQueueIndexFromSwapchain()
{
    WNDCLASSW wc = {};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"_2";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"_2", WS_OVERLAPPEDWINDOW, 0, 0, 1, 1, nullptr, nullptr, nullptr, nullptr);

    DXGI_SWAP_CHAIN_DESC1 sd = {};
    sd.Width = 1;
    sd.Height = 1;
    sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.SampleDesc.Count = 1;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    IDXGIFactory4* factory = nullptr;
    CreateDXGIFactory1(IID_PPV_ARGS(&factory));

    ID3D12Device* device = nullptr;
    D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));

    D3D12_COMMAND_QUEUE_DESC cqDesc = {};
    ID3D12CommandQueue* queue = nullptr;
    device->CreateCommandQueue(&cqDesc, IID_PPV_ARGS(&queue));


    IDXGISwapChain1* swapChain1 = nullptr;
    factory->CreateSwapChainForHwnd(queue, hwnd, &sd, nullptr, nullptr, &swapChain1);

    IDXGISwapChain3* swapChain = nullptr;
    swapChain1->QueryInterface(IID_PPV_ARGS(&swapChain));


    uint64_t val = (uint64_t)queue;
    uint64_t base = (uint64_t)swapChain;
    uint32_t index = 0;
    for (uint32_t i = 0; i < 0x40; ++i)
    {
        if (*(uint64_t*)(base + 8 * i) == val)
        {
            index = i;
            break;
        }
    }

    swapChain->Release();
    swapChain1->Release();
    queue->Release();
    device->Release();
    factory->Release();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return index;
}







void __attribute__((noinline)) shellcode_present_hook(void) {

    MAGIC_ASM

    __asm {
        movabs r10, 0xdeadbeefdeadbeef
        mov    QWORD PTR[r10 + 0x50], rcx
        mov    QWORD PTR[r10 + 0x88], rdx
        mov    QWORD PTR[r10 + 0x90], r8
#ifdef DIRECTX12
        add    rcx, 0x138
        mov    rcx, QWORD PTR[rcx]
        mov    QWORD PTR[r10 + 0x58], rcx
#endif
    begin_lock :
        mov    al, BYTE PTR[r10]
        cmp    al, 0x1
        jne  short fin
        mov    al, BYTE PTR[r10 + 0x1]
        cmp    al, 0x1
        jne  short begin_lock
        sub    rsp, 0x48
        mov    QWORD PTR[r10 + 0x68], rbx
        mov    QWORD PTR[r10 + 0x70], r14
        mov    rcx, QWORD PTR[r10 + 0x10]
        mov    rdx, QWORD PTR[r10 + 0x18]
        mov    r8, QWORD PTR[r10 + 0x20]
        mov    r9, QWORD PTR[r10 + 0x28]
        mov    r11, QWORD PTR[r10 + 0x30]
        mov    QWORD PTR[rsp + 0x20], r11
        mov    r11, QWORD PTR[r10 + 0x38]
        mov    QWORD PTR[rsp + 0x28], r11
        mov    r11, QWORD PTR[r10 + 0x40]
        mov    QWORD PTR[rsp + 0x30], r11
        mov    r11, QWORD PTR[r10 + 0x48]
        mov    QWORD PTR[rsp + 0x38], r11
        cmp    BYTE PTR[r10 + 0x80], 0x1
        je  short   vcall
        mov    rbx, QWORD PTR[r10 + 0x8]
        mov    r11w, WORD PTR[rbx]
        mov    WORD PTR[r10 + 0x98], r11w
    wait :
        mov    r11w, WORD PTR[r10 + 0x98]
        cmp    r11w, 0xb00b
        je   short jit
        cmp    r11w, 0xdead
        jne  short  wait
        jmp  short  execute
    jit :
        lea    rbx, [rip + jit_space]
        vmovups ymm0, YMMWORD PTR[r10 + 0xa8]
        vmovups YMMWORD PTR[rbx], ymm0
        vzeroupper
    execute :
        lea    r14, [rip + ret_addr]
        jmp    QWORD PTR[r10 + 0x60]
    vcall :
        xor r11, r11
        mov    r11w, WORD PTR[r10 + 0x82]
        mov    rbx, QWORD PTR[rcx]
        mov    rbx, QWORD PTR[rbx + r11 * 1]
        mov    QWORD PTR[r10 + 0x8], rbx
        mov    r11w, WORD PTR[rbx]
        mov    WORD PTR[r10 + 0x98], r11w
        jmp  short  wait
    ret_addr :
        pop    rbx
        movabs r10, 0xdeadbeefdeadbeef
        mov    rbx, QWORD PTR[r10 + 0x68]
        mov    r14, QWORD PTR[r10 + 0x70]
        mov    QWORD PTR[r10 + 0x78], rax
        mov    BYTE PTR[r10 + 0x1], 0x0
        add    rsp, 0x48
        jmp  short  begin_lock
    fin :
        mov    rcx,  QWORD PTR  [r10 + 0x50]
        mov    rdx,  QWORD PTR  [r10 + 0x88]
        mov    r8,   QWORD PTR  [r10 + 0x90]
        .byte 0xE9
        .byte 0x00
        .byte 0x00
        .byte 0x00
        .byte 0x00
    jit_space :
    }

    MAGIC_ASM
    MAGIC_ASM
}



size_t install_hook_present(CProcess& process, CExploit& exploit, int offset) {

    p_ipc = (present_ipc*)(exploit.get_LocalSharedMemory() + PAD_PRESENT_IPC);
    memset(p_ipc, 0, sizeof(*p_ipc));

    auto shell = get_shell(&shellcode_present_hook);
    shellcode obfuscated_shellcode{};

    obfuscated_shellcode.code = prepend_junk_ops(shell.code, shell.len, (std::rand() % 10) + 7, &obfuscated_shellcode.len);

#ifdef DIRECTX12
    auto index = GetQueueIndexFromSwapchain();
    *(uint32_t*)(&obfuscated_shellcode.code[0x1c + 3 + (obfuscated_shellcode.len - shell.len)]) = index * 8;
#endif  

    for (size_t i = 0; i <= obfuscated_shellcode.len - 8; ) {
        if (*(uint64_t*)(obfuscated_shellcode.code + i) == 0xdeadbeefdeadbeef) {
            *(uint64_t*)(obfuscated_shellcode.code + i) = exploit.get_RemoteSharedMemory() + PAD_PRESENT_IPC;
            i += 8;
        }
        else
            ++i;
    }

    uintptr_t dh64_present = exploit.ReadU64(process.discord_base + process.present_tramp_offset);

    uintptr_t dh64_rwx = dh64_present & 0xFFFFFFFFFFFFF000;

    uint32_t distance_to_present_tramp = dh64_present - (dh64_rwx + offset + obfuscated_shellcode.len);

    if (distance_to_present_tramp < 0x10000) {
        memcpy(obfuscated_shellcode.code + obfuscated_shellcode.len - 4, &distance_to_present_tramp, sizeof(uint32_t));

        exploit.WriteData(dh64_rwx + offset, obfuscated_shellcode.code, obfuscated_shellcode.len);
        exploit.WriteU64(process.discord_base + process.present_tramp_offset, dh64_rwx + offset);
    }
    while (!p_ipc->swapchain) {
        _mm_pause();
    }
    p_ipc->spoofhelper = process.discord_base + process.spoofcall_offset;
    return obfuscated_shellcode.len;
}

#include <d3dcompiler.h>
#pragma comment(lib, "d3dcompiler.lib")

#define BEGIN(id) \
    LARGE_INTEGER _##id##_start, _##id##_freq; \
    QueryPerformanceFrequency(&_##id##_freq); \
    QueryPerformanceCounter(&_##id##_start);

#define END(id) \
    LARGE_INTEGER _##id##_end; \
    QueryPerformanceCounter(&_##id##_end); \
    double _##id##_time = double(_##id##_end.QuadPart - _##id##_start.QuadPart) / double(_##id##_freq.QuadPart); \
    printf(#id " took %.6f ms\n", _##id##_time*1000);


void RenderThread(CExploit& exploit,D2DSharedRenderer& renderer, const wchar_t* shared_tex_name, HANDLE begin_event, HANDLE done_event) {

    typedef void (WINAPI* RtlCopyMemory_t)(void* Destination, const void* Source, size_t Length);
    RtlCopyMemory_t RtlCopyMemory = (RtlCopyMemory_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCopyMemory");

    typedef HRESULT(WINAPI* D3DCreateBlob_t)(SIZE_T Size, ID3DBlob** ppBlob);
    D3DCreateBlob_t D3DCreateBlob = (D3DCreateBlob_t)GetProcAddress(LoadLibraryA("d3dcompiler_47.dll"), "D3DCreateBlob");

    static struct dx12 {
        ID3D12Device* device = nullptr;
        ID3D12GraphicsCommandList* cmdList = nullptr;
        ID3D12RootSignature* rootSig = nullptr;
        ID3D12PipelineState* pso = nullptr;
        ID3D12DescriptorHeap* srvHeap = nullptr;
        ID3D12DescriptorHeap* rtvHeap = nullptr;
        ID3D12Resource* sharedTex = nullptr;
        HANDLE sharedHandle = nullptr;
        ID3D12Resource* vertexBuffer = nullptr;
        D3D12_VERTEX_BUFFER_VIEW vertexBufferView = {};
        UINT rtvDescriptorSize = 0;
        UINT backbufferCount = 0;
        FrameContext* frames = nullptr;
        bool initialized = false;
    } dx12;
    static bool isDx11 = false;

    static struct dx11 {
        bool initialized = false;
        ID3D11Buffer* vertexBuffer = nullptr;
        ID3D11VertexShader* vs = nullptr;
        ID3D11PixelShader* ps = nullptr;
        ID3D11InputLayout* inputLayout = nullptr;
        ID3D11ShaderResourceView* srv = nullptr;
        ID3D11SamplerState* sampler = nullptr;
        ID3D11BlendState* blend = nullptr;
        ID3D11Texture2D* sharedTex = nullptr;
        ID3D11Device1* device = nullptr;
        ID3D11DeviceContext1* ctx = nullptr;

    } dx11;

    struct D3D11StateBackup {
        ID3D11RenderTargetView* rtv = nullptr;
        ID3D11BlendState* blend = nullptr;
        FLOAT blendFactor[4]{};
        UINT sampleMask = 0;
        D3D11_VIEWPORT viewport{};
        UINT numViewports = 1;
        ID3D11InputLayout* inputLayout = nullptr;
        ID3D11Buffer* vertexBuffer = nullptr;
        UINT stride = 0, offset = 0;
        D3D11_PRIMITIVE_TOPOLOGY topology{};
        ID3D11VertexShader* vs = nullptr;
        ID3D11PixelShader* ps = nullptr;
        ID3D11ShaderResourceView* srv = nullptr;
        ID3D11SamplerState* sampler = nullptr;
    };

    while (1)
    {
        WaitForSingleObject(begin_event, INFINITE);

        p_ipc->lock = 1;

        if (!isDx11) {
            if (dx12.initialized == false) {
                ipc_call(exploit, &IDXGISwapChain::GetDevice, p_ipc->swapchain, __uuidof(ID3D12Device), (void**)&dx12.device);

                
                if (!dx12.device) {
                    isDx11 = true;
                    p_ipc->lock = 0;
                    SetEvent(done_event);
                    Sleep(0);

                    continue;
                }
                DXGI_SWAP_CHAIN_DESC desc = {};
                ipc_call(exploit, &IDXGISwapChain::GetDesc, p_ipc->swapchain, &desc);
                dx12.backbufferCount = desc.BufferCount;
                dx12.frames = new FrameContext[dx12.backbufferCount];
                ipc_call(exploit, &ID3D12Device::OpenSharedHandleByName, dx12.device, shared_tex_name, GENERIC_ALL, &dx12.sharedHandle);
                ipc_call(exploit, &ID3D12Device::OpenSharedHandle, dx12.device, dx12.sharedHandle, __uuidof(**(&dx12.sharedTex)), IID_PPV_ARGS_Helper(&dx12.sharedTex));

                D3D12_RESOURCE_DESC texDesc{};
                ipc_call(exploit, &ID3D12Resource::GetDesc, dx12.sharedTex, &texDesc);


                D3D12_DESCRIPTOR_HEAP_DESC srvHeapDesc = {};
                srvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
                srvHeapDesc.NumDescriptors = 1;
                srvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
                ipc_call(exploit, &ID3D12Device::CreateDescriptorHeap, dx12.device, &srvHeapDesc, IID_PPV_ARGS(&dx12.srvHeap));


                D3D12_CPU_DESCRIPTOR_HANDLE heap{};
                ipc_call(exploit, &ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart, dx12.srvHeap, &heap);


                D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
                srvDesc.Format = texDesc.Format;
                srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
                srvDesc.Texture2D.MipLevels = texDesc.MipLevels;
                ipc_call(exploit, &ID3D12Device::CreateShaderResourceView, dx12.device, dx12.sharedTex, &srvDesc, heap);

                D3D12_DESCRIPTOR_HEAP_DESC rtvDesc = {};
                rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
                rtvDesc.NumDescriptors = dx12.backbufferCount;
                ipc_call(exploit, &ID3D12Device::CreateDescriptorHeap, dx12.device, &rtvDesc, IID_PPV_ARGS(&dx12.rtvHeap));
                dx12.rtvDescriptorSize = ipc_call(exploit, &ID3D12Device::GetDescriptorHandleIncrementSize, dx12.device, D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

                D3D12_CPU_DESCRIPTOR_HANDLE rtvStart{};

                ipc_call(exploit, &ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart, dx12.rtvHeap, &rtvStart);


                for (UINT i = 0; i < dx12.backbufferCount; i++) {
                    FrameContext& ctx = dx12.frames[i];
                    ipc_call(exploit, &ID3D12Device::CreateCommandAllocator, dx12.device, D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&ctx.allocator));
                    ipc_call(exploit, &IDXGISwapChain::GetBuffer, p_ipc->swapchain, (uint64_t)i, IID_PPV_ARGS(&ctx.backbuffer));
                    ctx.rtvHandle = rtvStart;
                    ipc_call(exploit, &ID3D12Device::CreateRenderTargetView, dx12.device, ctx.backbuffer, nullptr, ctx.rtvHandle);
                    rtvStart.ptr += dx12.rtvDescriptorSize;
                }


                Vertex quad[] = {
                    { -1.0f, -1.0f, 0.0f, 0.0f, 1.0f },
                    { -1.0f,  1.0f, 0.0f, 0.0f, 0.0f },
                    {  1.0f, -1.0f, 0.0f, 1.0f, 1.0f },
                    {  1.0f,  1.0f, 0.0f, 1.0f, 0.0f },
                };

                D3D12_HEAP_PROPERTIES heapProps = { D3D12_HEAP_TYPE_UPLOAD };
                D3D12_RESOURCE_DESC resDesc = {};
                resDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
                resDesc.Width = sizeof(quad);
                resDesc.Height = 1;
                resDesc.DepthOrArraySize = 1;
                resDesc.MipLevels = 1;
                resDesc.SampleDesc.Count = 1;
                resDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
                ipc_call(exploit, &ID3D12Device::CreateCommittedResource, dx12.device, &heapProps, D3D12_HEAP_FLAG_NONE, &resDesc, D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, IID_PPV_ARGS(&dx12.vertexBuffer));

                void* p = 0;
                ipc_call(exploit, &ID3D12Resource::Map, dx12.vertexBuffer, 0, nullptr, &p);
                ipc_call(exploit, RtlCopyMemory, p, quad, sizeof(quad));
                ipc_call(exploit, &ID3D12Resource::Unmap, dx12.vertexBuffer, 0, nullptr);
                memset((void*)&p_ipc->arg[0], 0, sizeof(p_ipc->arg));
                dx12.vertexBufferView.BufferLocation = ipc_call(exploit, &ID3D12Resource::GetGPUVirtualAddress, dx12.vertexBuffer);

                dx12.vertexBufferView.StrideInBytes = sizeof(Vertex);
                dx12.vertexBufferView.SizeInBytes = sizeof(quad);

                const char* g_vsSrc =
                    "struct VS_INPUT { float4 pos : POSITION; float2 tex : TEXCOORD0; };"
                    "struct VS_OUTPUT { float4 pos : SV_POSITION; float2 tex : TEXCOORD0; };"
                    "VS_OUTPUT main(VS_INPUT input) {"
                    "  VS_OUTPUT output;"
                    "  output.pos = input.pos;"
                    "  output.tex = input.tex;"
                    "  return output;"
                    "}";

                const char* g_psSrc =
                    "Texture2D tex0 : register(t0);"
                    "SamplerState samp0 : register(s0);"
                    "struct VS_OUTPUT { float4 pos : SV_POSITION; float2 tex : TEXCOORD0; };"
                    "float4 main(VS_OUTPUT input) : SV_Target {"
                    "return tex0.Sample(samp0, input.tex);"
                    "}";

                ID3DBlob* local_vs = nullptr, * local_ps = nullptr, * local_sig = nullptr;
                ID3DBlob* vs = nullptr, * ps = nullptr, * sig = nullptr;
                D3DCompile(g_vsSrc, strlen(g_vsSrc), nullptr, nullptr, nullptr, "main", "vs_5_0", 0, 0, &local_vs, nullptr);
                D3DCompile(g_psSrc, strlen(g_psSrc), nullptr, nullptr, nullptr, "main", "ps_5_0", 0, 0, &local_ps, nullptr);


                ipc_call(exploit, D3DCreateBlob, local_vs->GetBufferSize(), &vs);
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA), local_vs->GetBufferPointer(), local_vs->GetBufferSize());
                ipc_call(exploit, RtlCopyMemory, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, vs), (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA), local_vs->GetBufferSize());

                ipc_call(exploit, D3DCreateBlob, local_ps->GetBufferSize(), &ps);
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA), local_ps->GetBufferPointer(), local_ps->GetBufferSize());
                ipc_call(exploit, RtlCopyMemory, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, ps), (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA), local_ps->GetBufferSize());

                D3D12_DESCRIPTOR_RANGE range = { D3D12_DESCRIPTOR_RANGE_TYPE_SRV, 1, 0 };
                D3D12_ROOT_PARAMETER param = {};
                param.ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
                param.DescriptorTable.NumDescriptorRanges = 1;
                param.DescriptorTable.pDescriptorRanges = &range;
                param.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

                D3D12_STATIC_SAMPLER_DESC samp = {};
                samp.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
                samp.AddressU = samp.AddressV = samp.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
                samp.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
                samp.ShaderRegister = 0;

                D3D12_ROOT_SIGNATURE_DESC sigDesc = {};
                sigDesc.NumParameters = 1;
                sigDesc.pParameters = &param;
                sigDesc.NumStaticSamplers = 1;
                sigDesc.pStaticSamplers = &samp;
                sigDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;
                D3D12SerializeRootSignature(&sigDesc, D3D_ROOT_SIGNATURE_VERSION_1, &local_sig, nullptr);

                ipc_call(exploit, D3DCreateBlob, local_sig->GetBufferSize(), &sig);
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA), local_sig->GetBufferPointer(), local_sig->GetBufferSize());
                void* remote_sig_ptr = (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, sig);
                ipc_call(exploit, RtlCopyMemory, remote_sig_ptr, (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA), local_sig->GetBufferSize());
                ipc_call(exploit, &ID3D12Device::CreateRootSignature, dx12.device, (uint64_t)0, remote_sig_ptr, local_sig->GetBufferSize(), IID_PPV_ARGS(&dx12.rootSig));

                strcpy((char*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x300), "POSITION");
                strcpy((char*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x300 + 9), "TEXCOORD");

                D3D12_INPUT_ELEMENT_DESC layout[] = {
                    { (char*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x300), 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0,  D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
                    { (char*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x309), 0, DXGI_FORMAT_R32G32_FLOAT,    0, 12, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
                };
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x312), layout, sizeof(layout));

                D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
                psoDesc.pRootSignature = dx12.rootSig;
                psoDesc.VS = { (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, vs), local_vs->GetBufferSize() };
                psoDesc.PS = { (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, ps), local_ps->GetBufferSize() };

                psoDesc.BlendState = {};
                psoDesc.BlendState.AlphaToCoverageEnable = true;
                //psoDesc.BlendState.IndependentBlendEnable = true;
                psoDesc.BlendState.RenderTarget[0].BlendEnable = true;

                psoDesc.BlendState.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;
                psoDesc.BlendState.RenderTarget[0].DestBlend = D3D12_BLEND_INV_SRC_ALPHA;
                psoDesc.BlendState.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
                psoDesc.BlendState.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
                psoDesc.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_INV_SRC_ALPHA;
                psoDesc.BlendState.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
                psoDesc.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
                psoDesc.SampleMask = UINT_MAX;

                {
                    D3D12_RASTERIZER_DESC& desc = psoDesc.RasterizerState;
                    desc.FillMode = D3D12_FILL_MODE_SOLID;
                    desc.CullMode = D3D12_CULL_MODE_NONE;
                    desc.FrontCounterClockwise = FALSE;
                    desc.DepthBias = D3D12_DEFAULT_DEPTH_BIAS;
                    desc.DepthBiasClamp = D3D12_DEFAULT_DEPTH_BIAS_CLAMP;
                    desc.SlopeScaledDepthBias = D3D12_DEFAULT_SLOPE_SCALED_DEPTH_BIAS;
                    desc.DepthClipEnable = true;
                    desc.MultisampleEnable = FALSE;
                    desc.AntialiasedLineEnable = FALSE;
                    desc.ForcedSampleCount = 0;
                    desc.ConservativeRaster = D3D12_CONSERVATIVE_RASTERIZATION_MODE_OFF;
                }
                {
                    D3D12_DEPTH_STENCIL_DESC& desc = psoDesc.DepthStencilState;
                    desc.DepthEnable = false;
                    desc.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
                    desc.DepthFunc = D3D12_COMPARISON_FUNC_ALWAYS;
                    desc.StencilEnable = false;
                    desc.FrontFace.StencilFailOp = desc.FrontFace.StencilDepthFailOp = desc.FrontFace.StencilPassOp = D3D12_STENCIL_OP_KEEP;
                    desc.FrontFace.StencilFunc = D3D12_COMPARISON_FUNC_ALWAYS;
                    desc.BackFace = desc.FrontFace;

                }
                psoDesc.InputLayout = { (D3D12_INPUT_ELEMENT_DESC*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x312), _countof(layout) };
                psoDesc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
                psoDesc.NumRenderTargets = 1;
                psoDesc.RTVFormats[0] = DXGI_FORMAT_B8G8R8A8_UNORM;
                psoDesc.SampleDesc.Count = 1;
                psoDesc.Flags = D3D12_PIPELINE_STATE_FLAG_NONE;

                ipc_call(exploit, &ID3D12Device::CreateGraphicsPipelineState, dx12.device, &psoDesc, IID_PPV_ARGS(&dx12.pso));
                ipc_call(exploit, &ID3DBlob::Release, vs);
                ipc_call(exploit, &ID3DBlob::Release, ps);
                ipc_call(exploit, &ID3DBlob::Release, sig);
                local_vs->Release(); local_ps->Release(); local_sig->Release();
                ipc_call(exploit, &ID3D12Device::CreateCommandList, dx12.device, (uint64_t)0, D3D12_COMMAND_LIST_TYPE_DIRECT, dx12.frames[0].allocator, nullptr, IID_PPV_ARGS(&dx12.cmdList));
                ipc_call(exploit, &ID3D12GraphicsCommandList::Close, dx12.cmdList);

                dx12.initialized = true;


            }

            UINT frameIdx = ipc_call(exploit, &IDXGISwapChain3::GetCurrentBackBufferIndex, (IDXGISwapChain3*)p_ipc->swapchain);


            FrameContext& ctx = dx12.frames[frameIdx];
            ipc_call(exploit, &ID3D12CommandAllocator::Reset, ctx.allocator);
            ipc_call(exploit, &ID3D12GraphicsCommandList::Reset, dx12.cmdList, ctx.allocator, dx12.pso);


            D3D12_RESOURCE_BARRIER barrier = {};
            barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
            barrier.Transition.pResource = ctx.backbuffer;
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
            barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
            ipc_call(exploit, &ID3D12GraphicsCommandList::ResourceBarrier, dx12.cmdList, (uint64_t)1, &barrier);
            ipc_call(exploit, &ID3D12GraphicsCommandList::OMSetRenderTargets, dx12.cmdList, (uint64_t)1, &ctx.rtvHandle, (uint64_t)0, nullptr);

            DXGI_SWAP_CHAIN_DESC desc = {};
            ipc_call(exploit, &IDXGISwapChain::GetDesc, p_ipc->swapchain, &desc);
            D3D12_VIEWPORT viewport = { 0, 0, (float)desc.BufferDesc.Width, (float)desc.BufferDesc.Height, 0.0f, 1.0f };
            D3D12_RECT scissor = { 0, 0, (LONG)desc.BufferDesc.Width, (LONG)desc.BufferDesc.Height };
            ipc_call(exploit, &ID3D12GraphicsCommandList::RSSetViewports, dx12.cmdList, (uint64_t)1, &viewport);
            ipc_call(exploit, &ID3D12GraphicsCommandList::RSSetScissorRects, dx12.cmdList, (uint64_t)1, &scissor);


            ipc_call(exploit, &ID3D12GraphicsCommandList::SetGraphicsRootSignature, dx12.cmdList, dx12.rootSig);
            ipc_call(exploit, &ID3D12GraphicsCommandList::SetPipelineState, dx12.cmdList, dx12.pso);
            ipc_call(exploit, &ID3D12GraphicsCommandList::SetDescriptorHeaps, dx12.cmdList, (uint64_t)1, &dx12.srvHeap);
            ipc_call(exploit, &ID3D12GraphicsCommandList::IASetPrimitiveTopology, dx12.cmdList, D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
            ipc_call(exploit, &ID3D12GraphicsCommandList::IASetVertexBuffers, dx12.cmdList, (uint64_t)0, (uint64_t)1, &dx12.vertexBufferView);
            D3D12_GPU_DESCRIPTOR_HANDLE gpuheap{};
            ipc_call(exploit, &ID3D12DescriptorHeap::GetGPUDescriptorHandleForHeapStart, dx12.srvHeap, &gpuheap);
            ipc_call(exploit, &ID3D12GraphicsCommandList::SetGraphicsRootDescriptorTable, dx12.cmdList, (uint64_t)0, gpuheap);
            ipc_call(exploit, &ID3D12GraphicsCommandList::DrawInstanced, dx12.cmdList, (uint64_t)4, (uint64_t)1, (uint64_t)0, (uint64_t)0);

            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
            ipc_call(exploit, &ID3D12GraphicsCommandList::ResourceBarrier, dx12.cmdList, (uint64_t)1, &barrier);
            ipc_call(exploit, &ID3D12GraphicsCommandList::Close, dx12.cmdList);
            ipc_call(exploit, &ID3D12CommandQueue::ExecuteCommandLists, p_ipc->queue, (uint64_t)1, (ID3D12CommandList* const*)&dx12.cmdList);
        }
        else {
            if (dx11.initialized == false) {

                ipc_call(exploit, &IDXGISwapChain::GetDevice, p_ipc->swapchain, __uuidof(ID3D11Device1), (void**)&dx11.device);
                if (!dx11.device) {
                    MessageBoxA(nullptr, "This is neither DX12 or DX11 game?", "Error", MB_OK);
                }


                // Quad vertices
                Vertex quad[] = {
                    { -1.0f, -1.0f, 0.0f, 0.0f, 1.0f },
                    { -1.0f,  1.0f, 0.0f, 0.0f, 0.0f },
                    {  1.0f, -1.0f, 0.0f, 1.0f, 1.0f },
                    {  1.0f,  1.0f, 0.0f, 1.0f, 0.0f },
                };

                D3D11_BUFFER_DESC vbDesc = {};
                vbDesc.Usage = D3D11_USAGE_IMMUTABLE;
                vbDesc.ByteWidth = sizeof(quad);
                vbDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x200), quad, sizeof(quad));
                D3D11_SUBRESOURCE_DATA vbData = { (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x200) };
                ipc_call(exploit, &ID3D11Device1::CreateBuffer, dx11.device, &vbDesc, &vbData, &dx11.vertexBuffer);


                const char* vsSrc =
                    "struct VS_INPUT { float4 pos : POSITION; float2 tex : TEXCOORD0; };"
                    "struct VS_OUTPUT { float4 pos : SV_POSITION; float2 tex : TEXCOORD0; };"
                    "VS_OUTPUT main(VS_INPUT input) {"
                    "  VS_OUTPUT output;"
                    "  output.pos = input.pos;"
                    "  output.tex = input.tex;"
                    "  return output;"
                    "}";

                // Pixel shader sampling from tex0
                const char* psSrc =
                    "Texture2D tex0 : register(t0);"
                    "SamplerState samp0 : register(s0);"
                    "struct VS_OUTPUT { float4 pos : SV_POSITION; float2 tex : TEXCOORD0; };"
                    "float4 main(VS_OUTPUT input) : SV_Target {"
                    "  return tex0.Sample(samp0, input.tex);"
                    "}";

                ID3DBlob* local_vs = nullptr, * local_ps = nullptr;
                ID3DBlob* vs = nullptr, * ps = nullptr;
                D3DCompile(vsSrc, strlen(vsSrc), nullptr, nullptr, nullptr, "main", "vs_5_0", 0, 0, &local_vs, nullptr);
                D3DCompile(psSrc, strlen(psSrc), nullptr, nullptr, nullptr, "main", "ps_5_0", 0, 0, &local_ps, nullptr);

                ipc_call(exploit, D3DCreateBlob, local_vs->GetBufferSize(), &vs);
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA), local_vs->GetBufferPointer(), local_vs->GetBufferSize());
                ipc_call(exploit, RtlCopyMemory, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, vs), (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA), local_vs->GetBufferSize());

                ipc_call(exploit, D3DCreateBlob, local_ps->GetBufferSize(), &ps);
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA), local_ps->GetBufferPointer(), local_ps->GetBufferSize());
                ipc_call(exploit, RtlCopyMemory, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, ps), (void*)(exploit.get_RemoteSharedMemory() + PAD_DATA), local_ps->GetBufferSize());

                strcpy((char*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x300), "POSITION");
                strcpy((char*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x300 + 9), "TEXCOORD");

                D3D11_INPUT_ELEMENT_DESC layout[] = {
                    { (char*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x300), 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0,  D3D11_INPUT_PER_VERTEX_DATA, 0 },
                    { (char*)(exploit.get_RemoteSharedMemory() + PAD_DATA + 0x309), 0, DXGI_FORMAT_R32G32_FLOAT,    0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
                };
                memcpy((void*)(exploit.get_LocalSharedMemory() + PAD_DATA + 0x312), layout, sizeof(layout));



                ipc_call(exploit, &ID3D11Device1::CreateInputLayout, dx11.device, layout, _countof(layout), (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, vs), ipc_call(exploit, &ID3DBlob::GetBufferSize, vs), &dx11.inputLayout);
                ipc_call(exploit, &ID3D11Device1::CreateVertexShader, dx11.device, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, vs), ipc_call(exploit, &ID3DBlob::GetBufferSize, vs), nullptr, &dx11.vs);
                ipc_call(exploit, &ID3D11Device1::CreatePixelShader, dx11.device, (void*)ipc_call(exploit, &ID3DBlob::GetBufferPointer, ps), ipc_call(exploit, &ID3DBlob::GetBufferSize, ps), nullptr, &dx11.ps);

                ipc_call(exploit, &ID3D11Device1::OpenSharedResourceByName, dx11.device, L"Global\\BlueSharedTex", DXGI_SHARED_RESOURCE_READ, __uuidof(ID3D11Texture2D), (void**)&dx11.sharedTex);
                local_vs->Release();
                local_ps->Release();
                D3D11_TEXTURE2D_DESC texDesc = {};
                ipc_call(exploit, &ID3D11Texture2D::GetDesc, dx11.sharedTex, &texDesc);


                D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                srvDesc.Format = texDesc.Format;
                srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                srvDesc.Texture2D.MostDetailedMip = 0;
                srvDesc.Texture2D.MipLevels = texDesc.MipLevels;

                ipc_call(exploit, &ID3D11Device1::CreateShaderResourceView, dx11.device, dx11.sharedTex, &srvDesc, &dx11.srv);

                D3D11_SAMPLER_DESC samp = {};
                samp.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
                samp.AddressU = samp.AddressV = samp.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
                ipc_call(exploit, &ID3D11Device1::CreateSamplerState, dx11.device, &samp, &dx11.sampler);

                // Alpha blending
                D3D11_BLEND_DESC b = {};
                b.RenderTarget[0].BlendEnable = TRUE;
                b.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
                b.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
                b.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
                b.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
                b.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
                b.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
                b.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
                ipc_call(exploit, &ID3D11Device1::CreateBlendState, dx11.device, &b, &dx11.blend);
                ipc_call(exploit, &ID3D11Device1::GetImmediateContext1, dx11.device, &dx11.ctx);
                dx11.initialized = true;
            }
            D3D11StateBackup s{};
            {
                //ipc_call(exploit, &ID3D11DeviceContext1::OMGetRenderTargets, dx11.ctx, 1, &s.rtv, nullptr);
                //ipc_call(exploit, &ID3D11DeviceContext1::OMGetBlendState, dx11.ctx, &s.blend, s.blendFactor, &s.sampleMask);
                //ipc_call(exploit, &ID3D11DeviceContext1::RSGetViewports, dx11.ctx, &s.numViewports, &s.viewport);
                ipc_call(exploit, &ID3D11DeviceContext1::IAGetInputLayout, dx11.ctx, &s.inputLayout);
                ipc_call(exploit, &ID3D11DeviceContext1::IAGetVertexBuffers, dx11.ctx, 0, 1, &s.vertexBuffer, &s.stride, &s.offset);
                ipc_call(exploit, &ID3D11DeviceContext1::IAGetPrimitiveTopology, dx11.ctx, &s.topology);
                //ipc_call(exploit, &ID3D11DeviceContext1::VSGetShader, dx11.ctx, &s.vs, nullptr, nullptr);
                //ipc_call(exploit, &ID3D11DeviceContext1::PSGetShader, dx11.ctx, &s.ps, nullptr, nullptr);
                //ipc_call(exploit, &ID3D11DeviceContext1::PSGetShaderResources, dx11.ctx, 0, 1, &s.srv);
                //ipc_call(exploit, &ID3D11DeviceContext1::PSGetSamplers, dx11.ctx, 0, 1, &s.sampler);
            }

            ID3D11Texture2D* backbuffer = nullptr;
            ID3D11RenderTargetView* rtv = nullptr;
            ipc_call(exploit, &IDXGISwapChain::GetBuffer, p_ipc->swapchain, 0, IID_PPV_ARGS(&backbuffer));
            ipc_call(exploit, &ID3D11Device1::CreateRenderTargetView, dx11.device, backbuffer, nullptr, &rtv);
            ipc_call(exploit, &ID3D11Texture2D::Release, backbuffer);

            float blendFactor[4] = { 0 };
            D3D11_VIEWPORT vp = { 0, 0, (FLOAT)1920, (FLOAT)1080, 0.0f, 1.0f };
            ipc_call(exploit, &ID3D11DeviceContext1::OMSetRenderTargets, dx11.ctx, 1, &rtv, nullptr);
            ipc_call(exploit, &ID3D11DeviceContext1::OMSetBlendState, dx11.ctx, dx11.blend, blendFactor, 0xFFFFFFFF);
            ipc_call(exploit, &ID3D11DeviceContext1::RSSetViewports, dx11.ctx, 1, &vp);

            UINT stride = sizeof(Vertex), offset = 0;

            ipc_call(exploit, &ID3D11DeviceContext1::IASetInputLayout, dx11.ctx, dx11.inputLayout);
            ipc_call(exploit, &ID3D11DeviceContext1::IASetVertexBuffers, dx11.ctx, (uint64_t)0, (uint64_t)1, &dx11.vertexBuffer, &stride, &offset);
            ipc_call(exploit, &ID3D11DeviceContext1::IASetPrimitiveTopology, dx11.ctx, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

            ipc_call(exploit, &ID3D11DeviceContext1::VSSetShader, dx11.ctx, dx11.vs, nullptr, 0);
            ipc_call(exploit, &ID3D11DeviceContext1::PSSetShader, dx11.ctx, dx11.ps, nullptr, 0);
            ipc_call(exploit, &ID3D11DeviceContext1::PSSetShaderResources, dx11.ctx, 0, 1, &dx11.srv);
            ipc_call(exploit, &ID3D11DeviceContext1::PSSetSamplers, dx11.ctx, 0, 1, &dx11.sampler);

            ipc_call(exploit, &ID3D11DeviceContext1::Draw, dx11.ctx, 4, 0);
            ipc_call(exploit, &ID3D11RenderTargetView::Release, rtv);

            {
                // ipc_call(exploit, &ID3D11DeviceContext1::OMSetRenderTargets, dx11.ctx, 1, &s.rtv, nullptr);
                // ipc_call(exploit, &ID3D11DeviceContext1::OMSetBlendState, dx11.ctx, s.blend, s.blendFactor, s.sampleMask);
                // ipc_call(exploit, &ID3D11DeviceContext1::RSSetViewports, dx11.ctx, s.numViewports, &s.viewport);
                ipc_call(exploit, &ID3D11DeviceContext1::IASetInputLayout, dx11.ctx, s.inputLayout);
                ipc_call(exploit, &ID3D11DeviceContext1::IASetVertexBuffers, dx11.ctx, 0, 1, &s.vertexBuffer, &s.stride, &s.offset);
                ipc_call(exploit, &ID3D11DeviceContext1::IASetPrimitiveTopology, dx11.ctx, s.topology);
                // ipc_call(exploit, &ID3D11DeviceContext1::VSSetShader, dx11.ctx, s.vs, nullptr, 0);
                // ipc_call(exploit, &ID3D11DeviceContext1::PSSetShader, dx11.ctx, s.ps, nullptr, 0);
                // ipc_call(exploit, &ID3D11DeviceContext1::PSSetShaderResources, dx11.ctx, 0, 1, &s.srv);
                // ipc_call(exploit, &ID3D11DeviceContext1::PSSetSamplers, dx11.ctx, 0, 1, &s.sampler);
            }

            {
                if (s.rtv)     ipc_call(exploit, &ID3D11RenderTargetView::Release, s.rtv);
                if (s.blend)   ipc_call(exploit, &ID3D11BlendState::Release, s.blend);
                if (s.inputLayout) ipc_call(exploit, &ID3D11InputLayout::Release, s.inputLayout);
                if (s.vertexBuffer) ipc_call(exploit, &ID3D11Buffer::Release, s.vertexBuffer);
                if (s.vs)      ipc_call(exploit, &ID3D11VertexShader::Release, s.vs);
                if (s.ps)      ipc_call(exploit, &ID3D11PixelShader::Release, s.ps);
                if (s.srv)     ipc_call(exploit, &ID3D11ShaderResourceView::Release, s.srv);
                if (s.sampler) ipc_call(exploit, &ID3D11SamplerState::Release, s.sampler);
            }

        }
        SetEvent(done_event);
        p_ipc->lock = 0;
        if (GetAsyncKeyState(VK_F1))
            break;
    }
}