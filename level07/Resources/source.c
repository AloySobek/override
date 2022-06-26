typedef unsigned char undefined;

typedef unsigned char byte;
typedef unsigned char dwfenc;
typedef unsigned int dword;
typedef long long longlong;
typedef unsigned long ulong;
typedef unsigned char undefined1;
typedef unsigned int undefined4;
typedef unsigned short ushort;
typedef unsigned short word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr
{
    byte eh_frame_hdr_version;                 // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding;          // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding;            // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry
{
    dword initial_loc; // Initial Location
    dword data_loc;    // Data location
};

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE
{
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[56];
};

struct _IO_marker
{
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct _IO_FILE FILE;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st
{
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef enum Elf32_DynTag_x86
{
    DT_NULL = 0,
    DT_NEEDED = 1,
    DT_PLTRELSZ = 2,
    DT_PLTGOT = 3,
    DT_HASH = 4,
    DT_STRTAB = 5,
    DT_SYMTAB = 6,
    DT_RELA = 7,
    DT_RELASZ = 8,
    DT_RELAENT = 9,
    DT_STRSZ = 10,
    DT_SYMENT = 11,
    DT_INIT = 12,
    DT_FINI = 13,
    DT_SONAME = 14,
    DT_RPATH = 15,
    DT_SYMBOLIC = 16,
    DT_REL = 17,
    DT_RELSZ = 18,
    DT_RELENT = 19,
    DT_PLTREL = 20,
    DT_DEBUG = 21,
    DT_TEXTREL = 22,
    DT_JMPREL = 23,
    DT_BIND_NOW = 24,
    DT_INIT_ARRAY = 25,
    DT_FINI_ARRAY = 26,
    DT_INIT_ARRAYSZ = 27,
    DT_FINI_ARRAYSZ = 28,
    DT_RUNPATH = 29,
    DT_FLAGS = 30,
    DT_PREINIT_ARRAY = 32,
    DT_PREINIT_ARRAYSZ = 33,
    DT_RELRSZ = 35,
    DT_RELR = 36,
    DT_RELRENT = 37,
    DT_ANDROID_REL = 1610612751,
    DT_ANDROID_RELSZ = 1610612752,
    DT_ANDROID_RELA = 1610612753,
    DT_ANDROID_RELASZ = 1610612754,
    DT_ANDROID_RELR = 1879040000,
    DT_ANDROID_RELRSZ = 1879040001,
    DT_ANDROID_RELRENT = 1879040003,
    DT_GNU_PRELINKED = 1879047669,
    DT_GNU_CONFLICTSZ = 1879047670,
    DT_GNU_LIBLISTSZ = 1879047671,
    DT_CHECKSUM = 1879047672,
    DT_PLTPADSZ = 1879047673,
    DT_MOVEENT = 1879047674,
    DT_MOVESZ = 1879047675,
    DT_FEATURE_1 = 1879047676,
    DT_POSFLAG_1 = 1879047677,
    DT_SYMINSZ = 1879047678,
    DT_SYMINENT = 1879047679,
    DT_GNU_HASH = 1879047925,
    DT_TLSDESC_PLT = 1879047926,
    DT_TLSDESC_GOT = 1879047927,
    DT_GNU_CONFLICT = 1879047928,
    DT_GNU_LIBLIST = 1879047929,
    DT_CONFIG = 1879047930,
    DT_DEPAUDIT = 1879047931,
    DT_AUDIT = 1879047932,
    DT_PLTPAD = 1879047933,
    DT_MOVETAB = 1879047934,
    DT_SYMINFO = 1879047935,
    DT_VERSYM = 1879048176,
    DT_RELACOUNT = 1879048185,
    DT_RELCOUNT = 1879048186,
    DT_FLAGS_1 = 1879048187,
    DT_VERDEF = 1879048188,
    DT_VERDEFNUM = 1879048189,
    DT_VERNEED = 1879048190,
    DT_VERNEEDNUM = 1879048191,
    DT_AUXILIARY = 2147483645,
    DT_FILTER = 2147483647
} Elf32_DynTag_x86;

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_x86
{
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
    PT_SHLIB = 5,
    PT_PHDR = 6,
    PT_TLS = 7,
    PT_GNU_EH_FRAME = 1685382480,
    PT_GNU_STACK = 1685382481,
    PT_GNU_RELRO = 1685382482
} Elf_ProgramHeaderType_x86;

struct Elf32_Phdr
{
    enum Elf_ProgramHeaderType_x86 p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel
{
    dword r_offset; // location to apply the relocation action
    dword r_info;   // the symbol table index and the type of relocation
};

typedef struct Gnu_BuildId Gnu_BuildId, *PGnu_BuildId;

struct Gnu_BuildId
{
    dword namesz;         // Length of name field
    dword descsz;         // Length of description field
    dword type;           // Vendor specific type
    char name[4];         // Build-id vendor name
    byte description[20]; // Build-id value
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym
{
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

struct Elf32_Dyn_x86
{
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType_x86
{
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_RELA = 4,
    SHT_HASH = 5,
    SHT_DYNAMIC = 6,
    SHT_NOTE = 7,
    SHT_NOBITS = 8,
    SHT_REL = 9,
    SHT_SHLIB = 10,
    SHT_DYNSYM = 11,
    SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY = 15,
    SHT_PREINIT_ARRAY = 16,
    SHT_GROUP = 17,
    SHT_SYMTAB_SHNDX = 18,
    SHT_ANDROID_REL = 1610612737,
    SHT_ANDROID_RELA = 1610612738,
    SHT_GNU_ATTRIBUTES = 1879048181,
    SHT_GNU_HASH = 1879048182,
    SHT_GNU_LIBLIST = 1879048183,
    SHT_CHECKSUM = 1879048184,
    SHT_SUNW_move = 1879048186,
    SHT_SUNW_COMDAT = 1879048187,
    SHT_SUNW_syminfo = 1879048188,
    SHT_GNU_verdef = 1879048189,
    SHT_GNU_verneed = 1879048190,
    SHT_GNU_versym = 1879048191
} Elf_SectionHeaderType_x86;

struct Elf32_Shdr
{
    dword sh_name;
    enum Elf_SectionHeaderType_x86 sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr
{
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

int _init(EVP_PKEY_CTX *ctx)

{
    int iVar1;

    __gmon_start__();
    frame_dummy();
    iVar1 = __do_global_ctors_aux();
    return iVar1;
}

void FUN_08048460(void)

{
    // WARNING: Treating indirect jump as call
    (*(code *)(undefined *)0x0)();
    return;
}

// WARNING: Unknown calling convention yet parameter storage is locked

int printf(char *__format, ...)

{
    int iVar1;

    iVar1 = printf(__format);
    return iVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked

int fflush(FILE *__stream)

{
    int iVar1;

    iVar1 = fflush(__stream);
    return iVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked

int getchar(void)

{
    int iVar1;

    iVar1 = getchar();
    return iVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked

char *fgets(char *__s, int __n, FILE *__stream)

{
    char *pcVar1;

    pcVar1 = fgets(__s, __n, __stream);
    return pcVar1;
}

void __stack_chk_fail(void)

{
    // WARNING: Subroutine does not return
    __stack_chk_fail();
}

// WARNING: Unknown calling convention yet parameter storage is locked

int puts(char *__s)

{
    int iVar1;

    iVar1 = puts(__s);
    return iVar1;
}

void __gmon_start__(void)

{
    __gmon_start__();
    return;
}

void __libc_start_main(void)

{
    __libc_start_main();
    return;
}

// WARNING: Unknown calling convention yet parameter storage is locked

void *memset(void *__s, int __c, size_t __n)

{
    void *pvVar1;

    pvVar1 = memset(__s, __c, __n);
    return pvVar1;
}

void __isoc99_scanf(void)

{
    __isoc99_scanf();
    return;
}

void _start(void)

{
    __libc_start_main(main);
    do
    {
        // WARNING: Do nothing block with infinite loop
    } while (true);
}

// WARNING: Removing unreachable block (ram,0x0804856a)
// WARNING: Removing unreachable block (ram,0x08048570)

void __do_global_dtors_aux(void)

{
    if (completed_6159 == '\0')
    {
        completed_6159 = '\x01';
    }
    return;
}

// WARNING: Removing unreachable block (ram,0x080485b8)

void frame_dummy(void)

{
    return;
}

void clear_stdin(void)

{
    int iVar1;

    do
    {
        iVar1 = getchar();
        if ((char)iVar1 == '\n')
        {
            return;
        }
    } while ((char)iVar1 != -1);
    return;
}

undefined4 get_unum(void)

{
    undefined4 local_10[3];

    local_10[0] = 0;
    fflush(stdout);
    __isoc99_scanf(&DAT_08048ad0, local_10);
    clear_stdin();
    return local_10[0];
}

void prog_timeout(void)

{
    code *pcVar1;

    pcVar1 = (code *)swi(0x80);
    (*pcVar1)();
    return;
}

undefined4 store_number(int param_1)

{
    uint uVar1;
    uint uVar2;
    undefined4 uVar3;

    printf(" Number: ");
    uVar1 = get_unum();
    printf(" Index: ");
    uVar2 = get_unum();
    if ((uVar2 % 3 == 0) || (uVar1 >> 0x18 == 0xb7))
    {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        uVar3 = 1;
    }
    else
    {
        *(uint *)(uVar2 * 4 + param_1) = uVar1;
        uVar3 = 0;
    }
    return uVar3;
}

undefined4 read_number(int param_1)

{
    int iVar1;

    printf(" Index: ");
    iVar1 = get_unum();
    printf(" Number at data[%u] is %u\n", iVar1, *(undefined4 *)(iVar1 * 4 + param_1));
    return 0;
}

undefined4 main(undefined4 param_1, char **param_2, char **param_3)

{
    char cVar1;
    int iVar2;
    uint uVar3;
    undefined4 *puVar4;
    char *pcVar5;
    byte *pbVar6;
    int in_GS_OFFSET;
    bool bVar7;
    bool bVar8;
    bool bVar9;
    byte bVar10;
    char **local_1c8;
    char **local_1c4;
    undefined4 local_1bc[100];
    undefined4 local_2c;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;
    undefined4 local_1c;
    undefined4 local_18;
    int local_14;

    bVar10 = 0;
    local_1c4 = param_2;
    local_1c8 = param_3;
    local_14 = *(int *)(in_GS_OFFSET + 0x14);
    local_2c = 0;
    local_28 = 0;
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_18 = 0;
    puVar4 = local_1bc;
    for (iVar2 = 100; iVar2 != 0; iVar2 = iVar2 + -1)
    {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
    }
    for (; *local_1c4 != (char *)0x0; local_1c4 = local_1c4 + 1)
    {
        uVar3 = 0xffffffff;
        pcVar5 = *local_1c4;
        do
        {
            if (uVar3 == 0)
                break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + (uint)bVar10 * -2 + 1;
        } while (cVar1 != '\0');
        memset(*local_1c4, 0, ~uVar3 - 1);
    }
    for (; *local_1c8 != (char *)0x0; local_1c8 = local_1c8 + 1)
    {
        uVar3 = 0xffffffff;
        pcVar5 = *local_1c8;
        do
        {
            if (uVar3 == 0)
                break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + (uint)bVar10 * -2 + 1;
        } while (cVar1 != '\0');
        memset(*local_1c8, 0, ~uVar3 - 1);
    }
    puts(
        "----------------------------------------------------\n  Welcome to wil\'s crappy number storage service!   \n----------------------------------------------------\n Commands:                                          \n    store - store a number into the data storage    \n    read  - read a number from the data storage     \n    quit  - exit the program                        \n----------------------------------------------------\n   wil has reserved some storage :>                 \n----------------------------------------------------\n");
    do
    {
        printf("Input command: ");
        local_2c = 1;
        fgets((char *)&local_28, 0x14, stdin);
        uVar3 = 0xffffffff;
        puVar4 = &local_28;
        do
        {
            if (uVar3 == 0)
                break;
            uVar3 = uVar3 - 1;
            cVar1 = *(char *)puVar4;
            puVar4 = (undefined4 *)((int)puVar4 + (uint)bVar10 * -2 + 1);
        } while (cVar1 != '\0');
        uVar3 = ~uVar3;
        bVar7 = uVar3 == 1;
        bVar9 = uVar3 == 2;
        *(undefined *)((int)&local_2c + uVar3 + 2) = 0;
        iVar2 = 5;
        puVar4 = &local_28;
        pbVar6 = (byte *)"store";
        do
        {
            if (iVar2 == 0)
                break;
            iVar2 = iVar2 + -1;
            bVar7 = *(byte *)puVar4 < *pbVar6;
            bVar9 = *(byte *)puVar4 == *pbVar6;
            puVar4 = (undefined4 *)((int)puVar4 + (uint)bVar10 * -2 + 1);
            pbVar6 = pbVar6 + (uint)bVar10 * -2 + 1;
        } while (bVar9);
        bVar8 = false;
        bVar7 = (!bVar7 && !bVar9) == bVar7;
        if (bVar7)
        {
            local_2c = store_number(local_1bc);
        }
        else
        {
            iVar2 = 4;
            puVar4 = &local_28;
            pbVar6 = &DAT_08048d61;
            do
            {
                if (iVar2 == 0)
                    break;
                iVar2 = iVar2 + -1;
                bVar8 = *(byte *)puVar4 < *pbVar6;
                bVar7 = *(byte *)puVar4 == *pbVar6;
                puVar4 = (undefined4 *)((int)puVar4 + (uint)bVar10 * -2 + 1);
                pbVar6 = pbVar6 + (uint)bVar10 * -2 + 1;
            } while (bVar7);
            bVar9 = false;
            bVar7 = (!bVar8 && !bVar7) == bVar8;
            if (bVar7)
            {
                local_2c = read_number(local_1bc);
            }
            else
            {
                iVar2 = 4;
                puVar4 = &local_28;
                pbVar6 = &DAT_08048d66;
                do
                {
                    if (iVar2 == 0)
                        break;
                    iVar2 = iVar2 + -1;
                    bVar9 = *(byte *)puVar4 < *pbVar6;
                    bVar7 = *(byte *)puVar4 == *pbVar6;
                    puVar4 = (undefined4 *)((int)puVar4 + (uint)bVar10 * -2 + 1);
                    pbVar6 = pbVar6 + (uint)bVar10 * -2 + 1;
                } while (bVar7);
                if ((!bVar9 && !bVar7) == bVar9)
                {
                    if (local_14 == *(int *)(in_GS_OFFSET + 0x14))
                    {
                        return 0;
                    }
                    // WARNING: Subroutine does not return
                    __stack_chk_fail();
                }
            }
        }
        if (local_2c == 0)
        {
            printf(" Completed %s command successfully\n", &local_28);
        }
        else
        {
            printf(" Failed to do %s command\n", &local_28);
        }
        local_28 = 0;
        local_24 = 0;
        local_20 = 0;
        local_1c = 0;
        local_18 = 0;
    } while (true);
}

// WARNING: Function: __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx
// WARNING: Removing unreachable block (ram,0x08048a30)
// WARNING: Removing unreachable block (ram,0x08048a38)

void __libc_csu_init(void)

{
    EVP_PKEY_CTX *in_stack_ffffffd4;

    _init(in_stack_ffffffd4);
    return;
}

void __libc_csu_fini(void)

{
    return;
}

// WARNING: This is an inlined function

void __i686_get_pc_thunk_bx(void)

{
    return;
}

void __do_global_ctors_aux(void)

{
    code *pcVar1;
    code **ppcVar2;

    if (__CTOR_LIST__ != (code *)0xffffffff)
    {
        ppcVar2 = &__CTOR_LIST__;
        pcVar1 = __CTOR_LIST__;
        do
        {
            ppcVar2 = ppcVar2 + -1;
            (*pcVar1)();
            pcVar1 = *ppcVar2;
        } while (pcVar1 != (code *)0xffffffff);
    }
    return;
}

void _fini(void)

{
    __do_global_dtors_aux();
    return;
}