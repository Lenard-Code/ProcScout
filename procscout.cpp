#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <atlbase.h>
#include <atlconv.h>
#include <shlobj.h>
#include <AclAPI.h>
#include <sddl.h>
#include <vector>
#include <sstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <set>
#include "resource.h"

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Crypt32.lib")

// Function to decode base64
std::string base64_decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Function to check if a process is running
bool isProcessRunning(const std::wstring& processName) {
    bool exists = false;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, processName.c_str())) {
                exists = true;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return exists;
}

// Function to check if a user has write permission on a folder
bool hasWritePermission(const std::wstring& folderPath) {
    std::wstring testFilePath = folderPath + L"\\testfile.tmp";
    HANDLE hFile = CreateFileW(testFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(hFile);
    return true;
}

// Function to trim leading and trailing quotes from a string
std::wstring trimQuotes(const std::wstring& str) {
    size_t start = str.find_first_not_of(L"\"");
    size_t end = str.find_last_not_of(L"\"");
    return (start == std::wstring::npos || end == std::wstring::npos) ? L"" : str.substr(start, end - start + 1);
}

bool isSafeDllSearchModeEnabled() {
    HKEY hKey;
    DWORD data;
    DWORD dataSize = sizeof(data);
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        if (result == ERROR_ACCESS_DENIED) {
            std::cerr << "[!] Error: Access denied. Insufficient privileges to open the registry key." << std::endl;
        }
        else {
            std::cerr << "[!] Error opening registry key. Error code: " << result << std::endl;
        }
        return false;
    }

    result = RegQueryValueEx(hKey, L"SafeDllSearchMode", NULL, NULL, (LPBYTE)&data, &dataSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        if (result == ERROR_ACCESS_DENIED) {
            std::cerr << "[!] Error: Access denied. Insufficient privileges to query the registry value." << std::endl;
        }
        else {
            std::cerr << "[!] Error querying registry value. Error code: " << result << std::endl;
        }
        return false;
    }

    // SafeDllSearchMode is enabled if the value is 1
    return data == 1;
}

// Function to extract embedded resource to a file
bool ExtractResource(const std::wstring& outputPath) {
    // Locate the resource
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PROCMON64), RT_RCDATA);
    if (!hResource) {
        std::cerr << "[!] Failed to find resource. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Load the resource
    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource) {
        std::cerr << "[!] Failed to load resource. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Lock the resource to get a pointer to the data
    LPVOID pLockedResource = LockResource(hLoadedResource);
    DWORD dwResourceSize = SizeofResource(NULL, hResource);
    if (!pLockedResource || dwResourceSize == 0) {
        std::cerr << "[!] Failed to lock resource. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Write the resource to a file
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "[!] Failed to open output file." << std::endl;
        return false;
    }
    outFile.write((const char*)pLockedResource, dwResourceSize);
    outFile.close();

    std::wcout << "[+] Procmon64.exe written to: " << outputPath << std::endl;
    return true;
}


int main() {

    // Get the path of the current executable
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(exePath).remove_filename();

    // Extract Procmon64.exe from resources
    std::wstring outPath = exeDir / L"Procmon64.exe";
    std::wcout << L"[+] Extracting to: " << outPath << std::endl; // Print the path
    if (!ExtractResource(outPath)) {
        std::cerr << "[-] Failed to extract Procmon64.exe" << std::endl;
        return 1;
    }

    // Decode base64 into config.pmc (Path ends with .dll and Result is NO NAME FOUND)
    std::string base64 = "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";
    std::string decoded = base64_decode(base64);
    std::ofstream configFile("config.pmc", std::ios::binary);
    configFile.write(decoded.c_str(), decoded.size());
    configFile.close();
    std::cout << "[+] PMC config file created\n";
    if (isSafeDllSearchModeEnabled()) {
        std::cout << "[+] Safe DLL Search Mode is enabled." << std::endl;
    }
    else {
        std::cout << "[!] Safe DLL Search Mode is not enabled or an error occurred." << std::endl;
    }
    // Run Procmon capture
    std::cout << "[+] Running Procmon capture\n";
    system("Procmon64.exe /AcceptEula /NoFilter /Runtime 60 /BackingFile Output.pml /Quiet /Minimized");

    // Wait for Procmon64 to finish
    while (isProcessRunning(L"Procmon64")) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Convert PML to CSV
    std::cout << "[+] Converting PML to CSV\n";
    system("Procmon64.exe /AcceptEula /SaveApplyFilter /LoadConfig config.pmc /SaveAs Output2.csv /OpenLog Output.pml");

    // Wait for Procmon64 to finish again
    while (isProcessRunning(L"Procmon64")) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Check paths in CSV
    std::cout << "[+] Checking paths for write ability\n";
    std::ifstream csvFile("Output2.csv");
    std::string line;
    int lineNumber = 0; // Debug: Track the line number
    std::set<std::wstring> writtenPaths; // Set to store written paths
    while (std::getline(csvFile, line)) {
        lineNumber++; // Debug: Increment line number
        if (lineNumber == 1) {
            continue;
        }
        std::stringstream ss(line);
        std::string item;
        std::vector<std::string> row;
        while (std::getline(ss, item, ',')) {
            row.push_back(item);
        }
        if (row.size() > 4) { // At least 5 fields in output csv
            std::wstring path = std::wstring(row[4].begin(), row[4].end());
            std::wstring process = std::wstring(row[1].begin(), row[1].end());
            // Extract folder path
            size_t pos = path.find_last_of(L"\\/");
            if (pos != std::wstring::npos) {
                std::wstring folderPath = trimQuotes(path.substr(0, pos));
                if (hasWritePermission(folderPath)) {
                    if (writtenPaths.find(path) == writtenPaths.end()) { // Check if path is already written
                        std::wcout << L"[+] Possible DLL hijack:\n" << "-- Path: " << path << "\n-- Process: " << process << std::endl;
                        writtenPaths.insert(path); // Add path to set
                    }
                }
                else {
                    //std::wcout << L"[-] No write permission on: " << folderPath << std::endl;
                }
            }
            else {
                std::wcout << L"[-] Could not extract folder path from: " << path << std::endl; // Debug: Handle case where folder path cannot be extracted
            }
        }
        else {
            std::cout << "[-] Row has less than 5 fields at line " << lineNumber << std::endl; // Debug: Print row field count issue
        }
    }

    return 0;
}