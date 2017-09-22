#include <pe-coff.hpp>
#include <string>
#include <iostream>
#include <fstream>

using namespace std;

void print_section_separator (const std::string &section_name)
{
    cout << section_name << endl;
    cout << "---------------------------" << endl;
}

template <typename T>
void print_info(const std::string &name, T value)
{
    cout << "\t" << name << ": " << value << endl;
}

void print_file_type(pecoff::FILE_TYPE type)
{
    print_section_separator("FILE TYPE");
    switch (type) {
    case pecoff::FILE_TYPE::PE_FILE:
        cout << "\tPE file." << endl;
        break;
    case pecoff::FILE_TYPE::COFF_FILE:
        cout << "\tCOFF file." << endl;
        break;
    default:
        cout << "\tUnknown file." << endl;
    }
}

void print_dos_header(pecoff::DOS_Header &header)
{
    print_section_separator("DOS HEADER");

    print_info("Signature", header.signature);
    print_info("LastSize", header.lastsize);
    print_info("NBlocks", header.nblocks);
    print_info("NReloc", header.nreloc);
    print_info("HDRSize", header.hdrsize);
    print_info("MinAlloc", header.minalloc);
    print_info("MaxAlloc", header.maxalloc);
    print_info("SS", header.ss);
    print_info("SP", header.sp);
    print_info("IP", header.ip);
    print_info("CS", header.cs);
    print_info("RelocPos", header.relocpos);
    print_info("NOverlay", header.noverlay);
    print_info("OEM_ID", header.oem_id);
    print_info("OEM_INFO", header.oem_info);
    print_info("E_LfaNew", header.e_lfanew);
}

string magic_to_string(uint16_t magic)
{
    switch (magic) {
    case pecoff::PE_FORMATS::PE32:
        return "PE32";
    case pecoff::PE_FORMATS::PE32_PLUS:
        return "PE32+";
    case pecoff::PE_FORMATS::ROM:
        return "ROM";
    default:
        return "Unknown";
    }
}

void print_coff_header(pecoff::COFF_Header &header)
{
    print_section_separator("COFF HEADER");

    print_info("Machine", header.machine);
    print_info("Number of section", header.number_of_section);
    print_info("Time Date Stamp", header.time_date_stamp);
    print_info("Pointer to Symbol Table", header.pointer_to_symbol_table);
    print_info("Number Of Symbols", header.number_of_symbols);
    print_info("Size Of Optional Header", header.size_of_optional_header);
    print_info("Characteristics", header.characteristics);
}

void print_optional_header_pe32(pecoff::Optional_Header_PE32 &header)
{
    print_section_separator("OPTIONAL HEADER (IMAGE ONLY)");

    print_info("Magic", magic_to_string(header.magic));
    print_info("Major Linker Version", header.major_linker_version);
    print_info("Minor Linker Version", header.minor_linker_version);
    print_info("Size Of Code", header.size_of_code);
    print_info("Size Of Initialized Data", header.size_of_initialized_data);
    print_info("Size Of Uninitialized Data", header.size_of_uninitialized_data);
    print_info("Address Of Entry Point", header.address_of_entry_point);
    print_info("Base Of Code", header.base_of_code);
    print_info("Base Of Data", header.base_of_data);
    print_info("Image Base", header.image_base);
    print_info("Section Alignment", header.section_alignment);
    print_info("File Alignment", header.file_alignment);
    print_info("Major Operating System Version", header.major_operating_system_version);
    print_info("Minor Operating System Version", header.minor_operating_system_version);
    print_info("Major Image Version", header.major_image_version);
    print_info("Minor Image Version", header.minor_image_version);
    print_info("Major Subsystem Version", header.major_subsystem_version);
    print_info("Minor Subsystem Version", header.minor_subsystem_version);
    print_info("Win32 Version Value", header.win32_version_value);
    print_info("Size Of Image", header.size_of_image);
    print_info("Size Of Headers", header.size_of_headers);
    print_info("Checksum", header.checksum);
    print_info("Subsystem", header.subsystem);
    print_info("DLL Characteristics", header.dll_characteristics);
    print_info("Size Of Stack Reserve", header.size_of_stack_reserve);
    print_info("Size Of Stack Commit", header.size_of_stack_commit);
    print_info("Size Of Heap Reserve", header.size_of_heap_reserve);
    print_info("Size Of Heap Commit", header.size_of_heap_commit);
    print_info("Loader_flags", header.loader_flags);
    print_info("Number Of RVA And Sizes", header.number_of_rva_and_sizes);
    print_info("Export Table", header.export_table);
    print_info("Import Table", header.import_table);
    print_info("Resource Table", header.resource_table);
    print_info("Exception Table", header.exception_table);
    print_info("Certificate Table", header.certificate_table);
    print_info("Base Relocation Table", header.base_relocation_table);
    print_info("Debug", header.debug);
    print_info("Architecture", header.architecture);
    print_info("Global Ptr", header.global_ptr);
    print_info("TLS Table", header.tls_table);
    print_info("Load Config Table", header.load_config_table);
    print_info("Bound Import", header.bound_import);
    print_info("IAT", header.iat);
    print_info("Delay Import Descriptor", header.delay_import_descriptor);
    print_info("CLR Runtime Header", header.clr_runtime_header);
    print_info("Reserved", header.reserved);
}

void print_optional_header_pe32_plus(pecoff::Optional_Header_PE32_Plus &header)
{
    print_section_separator("OPTIONAL HEADER (IMAGE ONLY)");

    print_info("Magic", magic_to_string(header.magic));
    print_info("Major Linker Version", header.major_linker_version);
    print_info("Minor Linker Version", header.minor_linker_version);
    print_info("Size Of Code", header.size_of_code);
    print_info("Size Of Initialized Data", header.size_of_initialized_data);
    print_info("Size Of Uninitialized Data", header.size_of_uninitialized_data);
    print_info("Address Of Entry Point", header.address_of_entry_point);
    print_info("Base Of Code", header.base_of_code);
    print_info("Image Base", header.image_base);
    print_info("Section Alignment", header.section_alignment);
    print_info("File Alignment", header.file_alignment);
    print_info("Major Operating System Version", header.major_operating_system_version);
    print_info("Minor Operating System Version", header.minor_operating_system_version);
    print_info("Major Image Version", header.major_image_version);
    print_info("Minor Image Version", header.minor_image_version);
    print_info("Major Subsystem Version", header.major_subsystem_version);
    print_info("Minor Subsystem Version", header.minor_subsystem_version);
    print_info("Win32 Version Value", header.win32_version_value);
    print_info("Size Of Image", header.size_of_image);
    print_info("Size Of Headers", header.size_of_headers);
    print_info("Checksum", header.checksum);
    print_info("Subsystem", header.subsystem);
    print_info("DLL Characteristics", header.dll_characteristics);
    print_info("Size Of Stack Reserve", header.size_of_stack_reserve);
    print_info("Size Of Stack Commit", header.size_of_stack_commit);
    print_info("Size Of Heap Reserve", header.size_of_heap_reserve);
    print_info("Size Of Heap Commit", header.size_of_heap_commit);
    print_info("Loader_flags", header.loader_flags);
    print_info("Number Of RVA And Sizes", header.number_of_rva_and_sizes);
    print_info("Export Table", header.export_table);
    print_info("Import Table", header.import_table);
    print_info("Resource Table", header.resource_table);
    print_info("Exception Table", header.exception_table);
    print_info("Certificate Table", header.certificate_table);
    print_info("Base Relocation Table", header.base_relocation_table);
    print_info("Debug", header.debug);
    print_info("Architecture", header.architecture);
    print_info("Global Ptr", header.global_ptr);
    print_info("TLS Table", header.tls_table);
    print_info("Load Config Table", header.load_config_table);
    print_info("Bound Import", header.bound_import);
    print_info("IAT", header.iat);
    print_info("Delay Import Descriptor", header.delay_import_descriptor);
    print_info("CLR Runtime Header", header.clr_runtime_header);
    print_info("Reserved", header.reserved);
}

void print_pe_file_info(ifstream &input)
{
    auto dos_header = pecoff::get_dos_header(input);
    print_dos_header(dos_header);

    auto coff_header_offset = dos_header.e_lfanew + sizeof(uint32_t);
    auto coff_header = pecoff::get_coff_header(input, coff_header_offset);
    print_coff_header(coff_header);

    if (coff_header.size_of_optional_header == 0) {
        cout << "Error: Optional header should not be empty" << endl;
        return;
    }

    auto optional_header_offset = input.tellg();
    if (coff_header.size_of_optional_header == sizeof(pecoff::Optional_Header_PE32)) {
        auto optional_header = pecoff::get_optional_header_pe32(input, optional_header_offset);
        print_optional_header_pe32(optional_header);

    } else if (coff_header.size_of_optional_header == sizeof(pecoff::Optional_Header_PE32_Plus)) {
        auto optional_header = pecoff::get_optional_header_pe32_plus(input, optional_header_offset);
        print_optional_header_pe32_plus(optional_header);
    }
}

void print_coff_file_info(ifstream &input)
{

}

void print_info(ifstream &input)
{
    auto file_type = pecoff::get_file_type(input);
    print_file_type(file_type);
    if (file_type == pecoff::FILE_TYPE::UNKNOWN_FILE) {
        return;
    }

    if (file_type == pecoff::FILE_TYPE::PE_FILE) {
        print_pe_file_info(input);
    } else {
        print_coff_file_info(input);
    }
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        cout << "Program must be called with one argument:" << endl << "dumpinfo.exe path_to_exe_or_object" << endl;
        return 0;
    }

    string path(argv[1]);
    ifstream file_input(path, ifstream::in | ifstream::binary);
    if (!file_input.is_open()) {
        cout << "Cannot open file " << path << endl;
        return 0;
    }

    print_info(file_input);

    return 0;
}
