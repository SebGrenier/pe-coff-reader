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
        uint32_t  e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
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
}

