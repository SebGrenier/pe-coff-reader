#include <pe-coff.hpp>
#include <iostream>
#include <fstream>

using namespace std;

void print_file_type(pecoff::FILE_TYPE type)
{
    cout << "File type:" << endl;
    switch (type) {
    case pecoff::FILE_TYPE::PE_FILE:
        cout << "\t PE file." << endl;
        break;
    case pecoff::FILE_TYPE::COFF_FILE:
        cout << "\t COFF file." << endl;
        break;
    default:
        cout << "\t Unknown file." << endl;
    }
}

void print_info(ifstream &input)
{
    auto file_type = pecoff::get_file_type(input);
    print_file_type(file_type);
    if (file_type == pecoff::FILE_TYPE::UNKNOWN_FILE) {
        return;
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
        cout << "Cannot open file " << path.c_str() << endl;
        return 0;
    }

    print_info(file_input);

    return 0;
}
