typedef unsigned char undefined;

typedef unsigned char byte;
typedef unsigned char dwfenc;
typedef unsigned int dword;
typedef unsigned char undefined1;
typedef unsigned int undefined4;
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

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st
{
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

int _init(EVP_PKEY_CTX *ctx)

{
    int iVar1;

    __gmon_start__();
    frame_dummy();
    iVar1 = __do_global_ctors_aux();
    return iVar1;
}

void FUN_08048370(void)

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

int puts(char *__s)

{
    int iVar1;

    iVar1 = puts(__s);
    return iVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked

int system(char *__command)

{
    int iVar1;

    iVar1 = system(__command);
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

// WARNING: Removing unreachable block (ram,0x0804843a)
// WARNING: Removing unreachable block (ram,0x08048440)

void __do_global_dtors_aux(void)

{
    if (completed_6159 == '\0')
    {
        completed_6159 = '\x01';
    }
    return;
}

// WARNING: Removing unreachable block (ram,0x08048488)

void frame_dummy(void)

{
    return;
}

bool main(void)

{
    int local_14[4];

    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");
    __isoc99_scanf(&DAT_08048636, local_14);
    if (local_14[0] != 0x149c)
    {
        puts("\nInvalid Password!");
    }
    else
    {
        puts("\nAuthenticated!");
        system("/bin/sh");
    }
    return local_14[0] != 0x149c;
}

// WARNING: Function: __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx
// WARNING: Removing unreachable block (ram,0x08048550)
// WARNING: Removing unreachable block (ram,0x08048558)

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