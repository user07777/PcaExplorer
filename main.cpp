/*
                                                                                --\____________________________________________________________________________________________________________________________________________/--
                                                                                --|                                                                                                                                            |--
                                                                                --|                                                 > H4X0R Script made by CyberByte                                                           |--
                                                      \___________________________|____________________________________________________________________________________________________________________________________________|____________________________/
                                                    --|                                                                                 [ SCRIPT DESCRIPTION ]                                                                                              |--
                                                    --|                                                                                                                                                                                                     |--
                                                    --|                                                                     Monitore todos arquivos abertos no windows.                                                                               |--
                                                    --|                                                             O PCA rastreia aplicativos para um conjunto de problemas de compatibilidade conhecidos no Windows 8.                                    |--
                                                    --|                                         O PCA rastreia os problemas, identifica as correções e fornece uma caixa de diálogo ao usuário com instruções para aplicar uma correção recomendada.        |--
                                                    --|                         Meu script funciona basicamente dumpando  á memória virtual do processo:explorer.exe, e em seguida o mesmo dump é filtrado via regex.Assim só retornando o valor esperado.  |--
                                                    --|_____________________________________________________________________________________________________________________________________________________________________________________________________|--
*/

#include <iostream>

#include <Windows.h>

#include <string>

#include <TlHelp32.h>

#include <regex>

#include <fstream>

#include <algorithm>


bool isChar(byte b) {
    return (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9;
}
auto tokenize(std::string s, std::string del = ",") {
    int start, end = -1 * del.size();
    std::vector<std::string> ret;
    do {
        start = end + del.size();
        end = s.find(del, start);
        ret.push_back(s.substr(start, end - start));
    } while (end != -1);
    return ret;
}


DWORD explorer_pid(const char* n) {
    PROCESSENTRY32 process_entry = {
        sizeof(PROCESSENTRY32)
    };
    HANDLE processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(processes_snapshot, &process_entry)) {
        while (Process32Next(processes_snapshot, &process_entry)) {
            if (_wcsicmp(process_entry.szExeFile, L"explorer.exe") == 0) {
                CloseHandle(processes_snapshot);
                return process_entry.th32ProcessID;
            }
        }
    }

    CloseHandle(processes_snapshot);
    return NULL;
}

std::vector < std::string > PcaExplorer() {
    std::string dump;
    DWORD pid = explorer_pid("");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    MEMORY_BASIC_INFORMATION minfo;
    byte fst = 0, snd = 0;
    bool uf = true, isUnicode = false;
    byte* buff{
        nullptr
    };
    for (unsigned char* p = 0;
        VirtualQueryEx(hProc, p, &minfo, sizeof(minfo))
        == sizeof(minfo);
        p += minfo.RegionSize) {
        if (minfo.Protect == PAGE_NOACCESS) continue;
        if (minfo.State == MEM_COMMIT && minfo.Type == MEM_PRIVATE) {
            byte* buff = new byte[(__int64)minfo.RegionSize];
            SIZE_T bytesRead = 0;
            ReadProcessMemory(hProc, (int*)p, buff, minfo.RegionSize, &bytesRead);
            for (int i = 0; i < bytesRead; i++) {
                bool cFlag = isChar(buff[i]);
                if (cFlag && uf && isUnicode && fst > 0) {
                    isUnicode = false;
                    if (dump.size() > 0) dump.erase(dump.end());
                    dump.push_back((char)buff[i]);
                }
                else if (cFlag) dump.push_back((char)buff[i]);
                else if (uf && buff[i] == 0 && isChar(fst) && isChar(snd)) isUnicode = true;
                else if (uf && buff[i] == 0 && isChar(fst) && isChar(snd) && dump.size() < 5) {
                    isUnicode = true;
                    dump.clear();
                    dump.push_back((char)fst);
                }
                else {
                    if (dump.size() >= 5 && dump.size() <= 1500) {
                        int l = dump.size();
                        if (isUnicode) l *= 2;
                    }
                }
            }
        }
    }
    std::vector<std::string> ret;
    const char* my_regex = "TRACE,.+,PcaClient,.+(\\w:\\\\.+\\.exe).+";
    std::regex r(my_regex);
    std::smatch m;
    int i = 0;
    std::sregex_iterator it(dump.begin(), dump.end(), r);
    std::sregex_iterator end;
    while (it != end) {
        for (unsigned i = 0; i < it->size(); ++i)
        {
            //if ((*it)[i].str().find("protected") == std::string::npos) {
                ret.push_back((*it)[i].str());
            //};
        }
        ++it;
    }
    return ret;
}
int  main(void)
{
    SetConsoleTitle(L"Pca Explorer");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
    std::cout << R"(
     ___________________________________________
    /                                           \
   (         > H4X0R Script made by CyberByte    ) 
    \___________________________________________/
 
_______________________________________________________________

)";
    std::regex r("(?:TRACE,[^,]*,[^,]*,PcaClient,[^,]*,|)([^,]+)");
    std::regex regex("TRACE,\\d+,\\d+,PcaClient,Excluded");
    std::regex regex1("TRACE,\\d+,\\d+,PcaClient,MonitorProcess");
    std::smatch m;
    std::vector<std::string> ret;
    for (const auto& str : PcaExplorer()) {
        int i = 0;
        std::sregex_iterator it(str.begin(), str.end(), r);
        std::sregex_iterator end;
        while (it != end) {
            for (unsigned i = 0; i < it->size(); ++i)
            {
                ret.push_back((*it)[i].str());
            }
            ++it;
        }
    }
    sort(ret.begin(), ret.end());
    ret.resize(std::distance(ret.begin(), unique(ret.begin(), ret.end())));
    ret.erase(std::remove_if(ret.begin(),ret.end(),[&regex](const std::string& j) {return std::regex_search(j, regex);}),ret.end());
    ret.erase(std::remove_if(ret.begin(),ret.end(),[&regex1](const std::string& j) {return std::regex_search(j, regex1);}),ret.end());
    for (const auto& i : ret) {
        if( i[1] == ':')
            std::cout << i << "\n";
    }
    system("pause");
}
