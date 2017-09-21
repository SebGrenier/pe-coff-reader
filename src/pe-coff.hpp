/*
 * PE-COFF File Header Reader.
 * Based on the Microsoft Portable Executable and Common Object File Format Specification
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx
 */
#pragma once
#include <fstream>

namespace pecoff {
    constexpr uint16_t DOS_SIGNATURE = 0x5a4d; // MZ
    constexpr uint32_t PE_OFFSET_ADDRESS = 0x3c;
    constexpr uint32_t PE_SIGNATURE = 0x00004550; // PE\0\0

    // Machine types
    namespace MACHINE_TYPES {
        constexpr uint16_t IMAGE_FILE_MACHINE_UNKNOWN = 0x0; // The contents of this field are assumed to be applicable to any machine type
        constexpr uint16_t IMAGE_FILE_MACHINE_AM33 = 0x1d3; // Matsushita AM33
        constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664; // x64
        constexpr uint16_t IMAGE_FILE_MACHINE_ARM = 0x1c0; // ARM little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_ARM64 = 0xaa64; // ARM64 little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_ARMNT = 0x1c4; // ARM Thumb - 2 little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_EBC = 0xebc; // EFI byte code
        constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x14c; // Intel 386 or later processors and compatible processors
        constexpr uint16_t IMAGE_FILE_MACHINE_IA64 = 0x200; // Intel Itanium processor family
        constexpr uint16_t IMAGE_FILE_MACHINE_M32R = 0x9041; // Mitsubishi M32R little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_MIPS16 = 0x266; // MIPS16
        constexpr uint16_t IMAGE_FILE_MACHINE_MIPSFPU = 0x366; // MIPS with FPU
        constexpr uint16_t IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466; // MIPS16 with FPU
        constexpr uint16_t IMAGE_FILE_MACHINE_POWERPC = 0x1f0; // Power PC little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1; // Power PC with floating point support
        constexpr uint16_t IMAGE_FILE_MACHINE_R4000 = 0x166; // MIPS little endian
        constexpr uint16_t IMAGE_FILE_MACHINE_RISCV32 = 0x5032; // RISC - V 32 - bit address space
        constexpr uint16_t IMAGE_FILE_MACHINE_RISCV64 = 0x5064; // RISC - V 64 - bit address space
        constexpr uint16_t IMAGE_FILE_MACHINE_RISCV128 = 0x5128; // RISC - V 128 - bit address space
        constexpr uint16_t IMAGE_FILE_MACHINE_SH3 = 0x1a2; // Hitachi SH3
        constexpr uint16_t IMAGE_FILE_MACHINE_SH3DSP = 0x1a3; // Hitachi SH3 DSP
        constexpr uint16_t IMAGE_FILE_MACHINE_SH4 = 0x1a6; // Hitachi SH4
        constexpr uint16_t IMAGE_FILE_MACHINE_SH5 = 0x1a8; // Hitachi SH5
        constexpr uint16_t IMAGE_FILE_MACHINE_THUMB = 0x1c2; // Thumb
        constexpr uint16_t IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169; // MIPS little - endian WCE v2
    }

    // Characteristics
    namespace CHARACTERISTICS
    {
        constexpr uint16_t IMAGE_FILE_RELOCS_STRIPPED = 0x0001; // Image only, Windows CE, and Microsoft Windows NT® and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
        constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002; // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
        constexpr uint16_t IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004; // COFF line numbers have been removed. This flag is deprecated and should be zero.
        constexpr uint16_t IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008; // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        constexpr uint16_t IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010; // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        constexpr uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020; // Application can handle > 2 GB addresses.
        // 0x0040; // This flag is reserved for future use.
        constexpr uint16_t IMAGE_FILE_BYTES_REVERSED_LO = 0x0080; // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        constexpr uint16_t IMAGE_FILE_32BIT_MACHINE = 0x0100; // Machine is based on a 32-bit-word architecture.
        constexpr uint16_t IMAGE_FILE_DEBUG_STRIPPED = 0x0200; // Debugging information is removed from the image file.
        constexpr uint16_t IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400; // If the image is on removable media, fully load it and copy it to the swap file.
        constexpr uint16_t IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800; // If the image is on network media, fully load it and copy it to the swap file.
        constexpr uint16_t IMAGE_FILE_SYSTEM = 0x1000; // The image file is a system file, not a user program.
        constexpr uint16_t IMAGE_FILE_DLL = 0x2000; // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        constexpr uint16_t IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000; // The file should be run only on a uniprocessor machine.
        constexpr uint16_t IMAGE_FILE_BYTES_REVERSED_HI = 0x8000; // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.

    }

    namespace PE_FORMATS
    {
        constexpr uint16_t PE32 = 0x10b;
        constexpr uint16_t PE32_PLUS = 0x20b; // PE32+ images allow for a 64-bit address space while limiting the image size to 2 gigabytes. Other PE32+ modifications are addressed in their respective sections.
        constexpr uint16_t ROM = 0x107;
    }

    enum class FILE_TYPE
    {
        UNKNOWN_FILE,
        PE_FILE,
        COFF_FILE
    };

    struct DOS_Header
    {
        uint16_t signature;
        uint16_t lastsize;
        uint16_t nblocks;
        uint16_t nreloc;
        uint16_t hdrsize;
        uint16_t minalloc;
        uint16_t maxalloc;
        uint16_t ss;
        uint16_t sp;
        uint16_t checksum;
        uint16_t ip;
        uint16_t cs;
        uint16_t relocpos;
        uint16_t noverlay;
        uint16_t reserved1[4];
        uint16_t oem_id;
        uint16_t oem_info;
        uint16_t reserved2[10];
        uint32_t e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
    };

    struct COFF_Header
    {
        uint16_t machine; // The number that identifies the type of target machine. For more information, see section 3.3.1, “Machine Types.”
        uint16_t number_of_section; // The number of sections. This indicates the size of the section table, which immediately follows the headers.
        uint32_t time_date_stamp; // The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.
        uint32_t pointer_to_symbol_table; // The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated.
        uint32_t number_of_symbols; // The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.
        uint16_t size_of_optional_header; // The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see section 3.4, “Optional Header (Image Only).”
        uint16_t characteristics; // The flags that indicate the attributes of the file. For specific flag values, see section 3.3.2, “Characteristics.”
    };

    struct Optional_Header_PE32
    {
        uint16_t magic; // The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
        uint8_t major_linker_version; // The linker major version number.
        uint8_t minor_linker_version; // The linker minor version number.
        uint32_t size_of_code; // The size of the code (text) section, or the sum of all code sections if there are multiple sections.
        uint32_t size_of_initialized_data; // The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
        uint32_t size_of_uninitialized_data; // The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
        uint32_t address_of_entry_point; // The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
        uint32_t base_of_code; // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
        uint32_t base_of_data; // The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
        uint32_t image_base; // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
        uint32_t section_alignment; // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
        uint32_t file_alignment; // The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture’s page size, then FileAlignment must match SectionAlignment.
        uint16_t major_operating_system_version; // The major version number of the required operating system.
        uint16_t minor_operating_system_version; // The minor version number of the required operating system.
        uint16_t major_image_version; // The major version number of the image.
        uint16_t minor_image_version; // The minor version number of the image.
        uint16_t major_subsystem_version; // The major version number of the subsystem.
        uint16_t minor_subsystem_version; // The minor version number of the subsystem.
        uint32_t win32_version_value; // Reserved, must be zero.
        uint32_t size_of_image; // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
        uint32_t size_of_headers; // The combined size of an MS DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
        uint32_t checksum; // The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
        uint16_t subsystem; // The subsystem that is required to run this image. For more information, see “Windows Subsystem” later in this specification.
        uint16_t dll_characteristics; // For more information, see “DLL Characteristics” later in this specification.
        uint32_t size_of_stack_reserve; // The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
        uint32_t size_of_stack_commit; // The size of the stack to commit.
        uint32_t size_of_heap_reserve; // The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
        uint32_t size_of_heap_commit; // The size of the local heap space to commit.
        uint32_t loader_flags; // Reserved, must be zero.
        uint32_t number_of_rva_and_sizes; // The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
        uint64_t export_table; // The export table address and size. For more information see section 6.3, “The .edata Section (Image Only).”
        uint64_t import_table; // The import table address and size. For more information, see section 6.4, “The .idata Section.”
        uint64_t resource_table; // The resource table address and size.For more information, see section 6.9, “The.rsrc Section.”
        uint64_t exception_table; // The exception table address and size. For more information, see section 6.5, “The .pdata Section.”
        uint64_t certificate_table; // The attribute certificate table address and size. For more information, see section 5.7, “The Attribute Certificate Table (Image Only).”
        uint64_t base_relocation_table; // The base relocation table address and size. For more information, see section 6.6, "The .reloc Section (Image Only)."
        uint64_t debug; // The debug data starting address and size. For more information, see section 6.1, “The .debug Section.”
        uint64_t architecture; // Reserved, must be 0
        uint64_t global_ptr; // The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
        uint64_t tls_table; // The thread local storage (TLS) table address and size. For more information, see section 6.7, “The .tls Section.”
        uint64_t load_config_table; // The load configuration table address and size. For more information, see section 6.8, “The Load Configuration Structure (Image Only).”
        uint64_t bound_import; // The bound import table address and size.
        uint64_t iat; // The import address table address and size. For more information, see section 6.4.4, “Import Address Table.”
        uint64_t delay_import_descriptor; // The delay import descriptor address and size. For more information, see section 5.8, “Delay-Load Import Tables (Image Only).”
        uint64_t clr_runtime_header; // The CLR runtime header address and size. For more information, see section 6.10, “The .cormeta Section (Object Only).”
        uint64_t reserved; // Reserved, must be zero
    };

    template <typename T>
    T read(std::ifstream &input)
    {
        T val;
        input.read(reinterpret_cast<char*>(&val), sizeof(T));
        return val;
    }

    inline bool is_machine_type (uint16_t value)
    {
        using namespace MACHINE_TYPES;
        return value == IMAGE_FILE_MACHINE_AM33 ||
            value == IMAGE_FILE_MACHINE_AMD64 ||
            value == IMAGE_FILE_MACHINE_ARM ||
            value == IMAGE_FILE_MACHINE_ARM64 ||
            value == IMAGE_FILE_MACHINE_ARMNT ||
            value == IMAGE_FILE_MACHINE_EBC ||
            value == IMAGE_FILE_MACHINE_I386 ||
            value == IMAGE_FILE_MACHINE_IA64 ||
            value == IMAGE_FILE_MACHINE_M32R ||
            value == IMAGE_FILE_MACHINE_MIPS16 ||
            value == IMAGE_FILE_MACHINE_MIPSFPU ||
            value == IMAGE_FILE_MACHINE_MIPSFPU16 ||
            value == IMAGE_FILE_MACHINE_POWERPC ||
            value == IMAGE_FILE_MACHINE_POWERPCFP ||
            value == IMAGE_FILE_MACHINE_R4000 ||
            value == IMAGE_FILE_MACHINE_RISCV32 ||
            value == IMAGE_FILE_MACHINE_RISCV64 ||
            value == IMAGE_FILE_MACHINE_RISCV128 ||
            value == IMAGE_FILE_MACHINE_SH3 ||
            value == IMAGE_FILE_MACHINE_SH3DSP ||
            value == IMAGE_FILE_MACHINE_SH4 ||
            value == IMAGE_FILE_MACHINE_SH5 ||
            value == IMAGE_FILE_MACHINE_THUMB ||
            value == IMAGE_FILE_MACHINE_WCEMIPSV2;
    }

    inline FILE_TYPE get_file_type(std::ifstream &input)
    {
        input.seekg(0);
        auto first_two_bytes = read<uint16_t>(input);
        if (first_two_bytes == DOS_SIGNATURE) {
            // Check if there is a PE signature.
            input.seekg(PE_OFFSET_ADDRESS);
            auto pe_offset = read<uint32_t>(input);
            input.seekg(pe_offset);
            auto pe_signature = read<uint32_t>(input);
            if (pe_signature == PE_SIGNATURE)
                return FILE_TYPE::PE_FILE;
        } else if (is_machine_type(first_two_bytes)) {
            return FILE_TYPE::COFF_FILE;
        }
        return FILE_TYPE::UNKNOWN_FILE;
    }

    inline DOS_Header get_dos_header(std::ifstream &input, int offset = 0)
    {
        input.seekg(offset);
        return read<DOS_Header>(input);
    }

    inline COFF_Header get_coff_header(std::ifstream &input, int offset = 0)
    {
        input.seekg(offset);
        return read<COFF_Header>(input);
    }
}

