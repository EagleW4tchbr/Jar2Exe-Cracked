#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <conio.h>  // For _getwch()
#include <vector>
#include <string>
#include <optional>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <tuple>
#include <cstdint>  // For uint8_t, etc.
#include <locale>   // For conversions if needed
#include "MinHook.h"

using namespace std;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;
using i64 = int64_t;

const size_t INSTR_OLD_SIZE = 6;
const size_t INSTR_NEW_SIZE = 6;

struct Patch {
    u64 va;
    optional<u64> target;
};

vector<Patch> DEFAULT_PATCHES = {
    {0x001580d6ULL, 0x001580dcULL},
    {0x001581daULL, 0x001581e0ULL},
    {0x004164c9ULL, nullopt},
    {0x004161ebULL, nullopt},
};

struct Phdr {
    u32 type;
    u32 flags;
    u64 offset;
    u64 vaddr;
    u64 paddr;
    u64 filesz;
    u64 memsz;
    u64 align;
};

struct Section {
    string name;
    u32 vsize;
    u32 vaddr;
    u32 rsize;
    u32 roff;
};

template<typename T>
T read_int(ifstream& f, bool be) {
    if constexpr (sizeof(T) == 2) {
        u8 b[2];
        f.read((char*)b, 2);
        if (!f) throw runtime_error("Read failed");
        return be ? (u16)((b[1] << 8) | b[0]) : (u16)(b[0] | (b[1] << 8));
    } else if constexpr (sizeof(T) == 4) {
        u8 b[4];
        f.read((char*)b, 4);
        if (!f) throw runtime_error("Read failed");
        if (!be) {
            return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
        } else {
            return (u32)b[3] | ((u32)b[2] << 8) | ((u32)b[1] << 16) | ((u32)b[0] << 24);
        }
    } else if constexpr (sizeof(T) == 8) {
        u8 b[8];
        f.read((char*)b, 8);
        if (!f) throw runtime_error("Read failed");
        u64 val = 0;
        for (int i = 0; i < 8; ++i) {
            u64 byte_val = b[be ? (7 - i) : i];
            val |= (byte_val << (i * 8));
        }
        return val;
    }
    throw runtime_error("Unsupported type");
}

u16 read_u16_le(ifstream& f) {
    u8 b[2];
    f.read((char*)b, 2);
    if (!f) throw runtime_error("Read failed");
    return (u16)(b[0] | (b[1] << 8));
}

u32 read_u32_le(ifstream& f) {
    u8 b[4];
    f.read((char*)b, 4);
    if (!f) throw runtime_error("Read failed");
    return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

u64 read_u64_le(ifstream& f) {
    u8 b[8];
    f.read((char*)b, 8);
    if (!f) throw runtime_error("Read failed");
    u64 val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= ((u64)b[i] << (i * 8));
    }
    return val;
}

tuple<bool, string, vector<Phdr>> parse_elf_program_headers(const string& path) {
    ifstream f(path, ios::binary);
    vector<u8> ident(16);
    f.read((char*)ident.data(), 16);
    if (ident.size() < 16 || ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
        throw runtime_error("Not an ELF file");
    }
    bool is64 = (ident[4] == 2);
    bool be = (ident[5] == 2);
    string endian_str = be ? ">" : "<";
    f.seekg(16);
    u16 e_type = read_int<u16>(f, be);
    u16 e_machine = read_int<u16>(f, be);
    u32 e_version = read_int<u32>(f, be);
    u64 e_entry = is64 ? read_int<u64>(f, be) : (u64)read_int<u32>(f, be);
    u64 e_phoff = is64 ? read_int<u64>(f, be) : (u64)read_int<u32>(f, be);
    u64 e_shoff = is64 ? read_int<u64>(f, be) : (u64)read_int<u32>(f, be);
    u32 e_flags = read_int<u32>(f, be);
    u16 e_ehsize = read_int<u16>(f, be);
    u16 e_phentsize = read_int<u16>(f, be);
    u16 e_phnum = read_int<u16>(f, be);
    u16 e_shentsize = read_int<u16>(f, be);
    u16 e_shnum = read_int<u16>(f, be);
    u16 e_shstrndx = read_int<u16>(f, be);
    vector<Phdr> phdrs;
    if (e_phoff >= (is64 ? 64 : 52)) {
        f.seekg(e_phoff);
        u16 num_to_read = min(e_phnum, (u16)32);
        for (int i = 0; i < num_to_read; ++i) {
            Phdr p;
            if (is64) {
                p.type = read_int<u32>(f, be);
                p.flags = read_int<u32>(f, be);
                p.offset = read_int<u64>(f, be);
                p.vaddr = read_int<u64>(f, be);
                p.paddr = read_int<u64>(f, be);
                p.filesz = read_int<u64>(f, be);
                p.memsz = read_int<u64>(f, be);
                p.align = read_int<u64>(f, be);
            } else {
                p.type = read_int<u32>(f, be);
                p.offset = (u64)read_int<u32>(f, be);
                p.vaddr = (u64)read_int<u32>(f, be);
                p.paddr = (u64)read_int<u32>(f, be);
                p.filesz = (u64)read_int<u32>(f, be);
                p.memsz = (u64)read_int<u32>(f, be);
                p.flags = read_int<u32>(f, be);
                p.align = (u64)read_int<u32>(f, be);
            }
            phdrs.push_back(p);
        }
    }
    return {is64, endian_str, phdrs};
}

optional<tuple<u64, string, u64>> elf_try_map_va_to_offset(const vector<Phdr>& phdrs, u64 va) {
    vector<Phdr> loads;
    for (const auto& p : phdrs) {
        if (p.type == 1) loads.push_back(p);
    }
    if (loads.empty()) return nullopt;
    sort(loads.begin(), loads.end(), [](const Phdr& a, const Phdr& b) { return a.vaddr < b.vaddr; });
    for (const auto& p : loads) {
        if (p.vaddr <= va && va < p.vaddr + p.memsz) {
            u64 off = p.offset + (va - p.vaddr);
            return make_tuple(off, "direct", va);
        }
    }
    if (!loads.empty()) {
        u64 lowest = loads[0].vaddr;
        u64 adj_va = va - lowest;
        for (const auto& p : loads) {
            u64 start = p.vaddr - lowest;
            u64 end = start + p.memsz;
            if (start <= adj_va && adj_va < end) {
                u64 off = p.offset + (adj_va - start);
                ostringstream oss;
                oss << "sub_lowest_0x" << hex << setw(8) << setfill('0') << (u32)lowest;
                return make_tuple(off, oss.str(), va);
            }
        }
    }
    u64 guess = 0x00100000ULL;
    u64 adj_va2 = va - guess;
    for (const auto& p : loads) {
        if (p.vaddr <= adj_va2 && adj_va2 < p.vaddr + p.memsz) {
            u64 off = p.offset + (adj_va2 - p.vaddr);
            return make_tuple(off, "sub_0x00100000", va);
        }
    }
    return nullopt;
}

tuple<bool, u64, vector<Section>> parse_pe_sections(const string& path) {
    ifstream f(path, ios::binary);
    f.seekg(0x3C);
    u32 e_lfanew = read_u32_le(f);
    f.seekg(e_lfanew);
    u8 pesig[4];
    f.read((char*)pesig, 4);
    if (pesig[0] != 'P' || pesig[1] != 'E' || pesig[2] != 0 || pesig[3] != 0) {
        throw runtime_error("Not a PE file (PE signature missing)");
    }
    u16 machine = read_u16_le(f);
    u16 num_sections = read_u16_le(f);
    f.seekg(e_lfanew + 4 + 16);
    u16 opt_size = read_u16_le(f);
    f.seekg(e_lfanew + 4 + 20);
    u16 magic = read_u16_le(f);
    bool is64 = (magic == 0x20B);
    u64 image_base;
    streampos image_base_offset = is64 ? (e_lfanew + 4 + 20 + 24) : (e_lfanew + 4 + 20 + 28);
    f.seekg(image_base_offset);
    if (is64) {
        image_base = read_u64_le(f);
    } else {
        image_base = read_u32_le(f);
    }
    streampos section_start = e_lfanew + 4 + 20 + opt_size;
    f.seekg(section_start);
    vector<Section> sections;
    u16 num_to_read = min(num_sections, (u16)32);
    for (int i = 0; i < num_to_read; ++i) {
        u8 namebuf[8];
        f.read((char*)namebuf, 8);
        string name;
        for (int j = 0; j < 8; ++j) {
            if (namebuf[j] != 0) name += (char)namebuf[j];
        }
        u32 virtual_size = read_u32_le(f);
        u32 virtual_address = read_u32_le(f);
        u32 raw_size = read_u32_le(f);
        u32 raw_offset = read_u32_le(f);
        f.seekg(16, ios::cur);
        sections.push_back({name, virtual_size, virtual_address, raw_size, raw_offset});
    }
    return {is64, image_base, sections};
}

optional<u64> pe_va_to_file_offset(const string& path, u64 va) {
    auto [is64, image_base, sections] = parse_pe_sections(path);
    u64 rva = va - image_base;
    for (const auto& s : sections) {
        u64 start = s.vaddr;
        u64 end = start + max((u64)s.vsize, (u64)s.rsize);
        if (start <= rva && rva < end) {
            return s.roff + (rva - start);
        }
    }
    return nullopt;
}

optional<u64> compute_target_from_original(const vector<u8>& orig_bytes, u64 va_used) {
    if (orig_bytes.size() < 6) return nullopt;
    if (orig_bytes[0] == 0x0F && orig_bytes[1] == 0x85) {
        i32 orig_rel = (i32)((u32)orig_bytes[2] | ((u32)orig_bytes[3] << 8) | ((u32)orig_bytes[4] << 16) | ((u32)orig_bytes[5] << 24));
        return va_used + 6 + (i64)orig_rel;
    }
    return nullopt;
}

i32 compute_rel32_for_e9(u64 va_instr, u64 target_va) {
    i64 diff = (i64)target_va - ((i64)va_instr + 5);
    if (diff < INT32_MIN || diff > INT32_MAX) {
        throw runtime_error("rel32 out of 32-bit signed range");
    }
    return (i32)diff;
}

pair<vector<u8>, i32> write_patch_at_offset(fstream& f, u64 file_offset, u64 va_instr, u64 target_va) {
    i32 rel = compute_rel32_for_e9(va_instr, target_va);
    vector<u8> new_bytes = {
        0xE9,
        (u8)(rel & 0xFF),
        (u8)((rel >> 8) & 0xFF),
        (u8)((rel >> 16) & 0xFF),
        (u8)((rel >> 24) & 0xFF),
        0x90
    };
    f.seekp(file_offset);
    f.write((char*)new_bytes.data(), new_bytes.size());
    if (!f) throw runtime_error("Write failed");
    f.flush();
    return {new_bytes, rel};
}

string bytes_to_hex(const vector<u8>& bytes) {
    ostringstream oss;
    oss << hex << uppercase;
    for (u8 b : bytes) {
        oss << setw(2) << setfill('0') << (int)b;
    }
    return oss.str();
}

string hex8(u64 val) {
    ostringstream oss;
    oss << hex << uppercase << setw(8) << setfill('0') << static_cast<u32>(val);
    return oss.str();
}

bool looks_like_pe_va(u64 va) {
    return va >= 0x00400000ULL;
}

bool looks_like_elf_va(u64 va) {
    return (0x00010000ULL <= va && va < 0x00300000ULL) || (va < 0x00100000ULL);
}

void copy_file(const string& src, const string& dst) {
    ifstream ifs(src, ios::binary);
    if (!ifs) throw runtime_error("Cannot read source file for backup");
    ofstream ofs(dst, ios::binary);
    if (!ofs) throw runtime_error("Cannot write backup file");
    ofs << ifs.rdbuf();
    if (!ofs) throw runtime_error("Backup copy failed");
}
// Global bool for debug console (set to false to disable)
bool SHOW_DEBUG_CONSOLE = false;
bool CREATE_BACKUP = false;  // Set to false → no .bak file

void patch_file(const string& path, const vector<Patch>& patches, bool dry_run, bool force) {
    bool is_elf = false;
    bool is_pe = false;
    {
        ifstream testf(path, ios::binary);
        u8 magic[4];
        testf.read((char*)magic, 4);
        is_elf = (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F');
    }
    try {
        ifstream f(path, ios::binary);
        f.seekg(0x3C);
        u32 e_lfanew = read_u32_le(f);
        f.seekg(e_lfanew);
        u8 pesig[4];
        f.read((char*)pesig, 4);
        is_pe = (pesig[0] == 'P' && pesig[1] == 'E' && pesig[2] == 0 && pesig[3] == 0);
    } catch (...) {
        is_pe = false;
    }
    if (!(is_elf || is_pe)) {
        throw runtime_error("Unknown file format (neither ELF nor PE)");
    }
    vector<Phdr> phdrs;
    u64 image_base = 0;
    vector<Section> pe_sections;
    vector<Phdr> loads;
    if (is_elf) {
        auto [is64, endian, phdrs_tmp] = parse_elf_program_headers(path);
        phdrs = phdrs_tmp;
        for (const auto& p : phdrs) {
            if (p.type == 1) loads.push_back(p);
        }
        sort(loads.begin(), loads.end(), [](const Phdr& a, const Phdr& b) { return a.vaddr < b.vaddr; });
    } else {
        auto [is64, ib, secs] = parse_pe_sections(path);
        image_base = ib;
        pe_sections = secs;
    }
    ios::openmode mode = ios::binary | ios::in;
    if (!dry_run) mode |= ios::out;
    fstream f(path, mode);
    if (!f) throw runtime_error("Cannot open file for patching");
    for (const auto& patch : patches) {
        u64 va = patch.va;
        optional<u64> tgt = patch.target;
        optional<u64> file_off_opt;
        string strat;
        u64 va_used = va;
        if (is_elf) {
            auto res_opt = elf_try_map_va_to_offset(phdrs, va);
            if (res_opt) {
                auto [off, s, _] = *res_opt;
                file_off_opt = off;
                strat = s;
            }
        } else {
            auto off_opt = pe_va_to_file_offset(path, va);
            if (off_opt) {
                file_off_opt = *off_opt;
                strat = "pe_direct";
            }
        }
        if (!file_off_opt) {
            if (is_elf && looks_like_pe_va(va)) continue;
            if (is_pe && looks_like_elf_va(va)) continue;
            continue;
        }
        u64 file_off = *file_off_opt;
        f.seekg(file_off);
        vector<u8> orig(INSTR_OLD_SIZE);
        f.read((char*)orig.data(), INSTR_OLD_SIZE);
        if (f.gcount() != (streamsize)INSTR_OLD_SIZE) continue;
        u64 computed_target;
        if (tgt) {
            computed_target = *tgt;
        } else {
            auto comp_opt = compute_target_from_original(orig, va_used);
            if (!comp_opt) {
                if (!force) continue;
                continue;
            }
            computed_target = *comp_opt;
        }
        try {
            if (dry_run) {
                i32 rel = compute_rel32_for_e9(va_used, computed_target);
                vector<u8> new_bytes = {
                    0xE9, (u8)(rel & 0xFF), (u8)((rel >> 8) & 0xFF),
                    (u8)((rel >> 16) & 0xFF), (u8)((rel >> 24) & 0xFF), 0x90
                };
            } else {
                auto [nb, r] = write_patch_at_offset(f, file_off, va_used, computed_target);
            }
        } catch (const exception& e) {
            continue;
        }
        }  // end of for loop over patches

    // === BACKUP LOGIC (WITH TOGGLE) ===
    if (CREATE_BACKUP) {
        string bak = path + ".bak";
        try {
            copy_file(path, bak);
            if (SHOW_DEBUG_CONSOLE) {
                wprintf(L"Backup created: %hs\n", bak.c_str());
            }
        } catch (const std::exception& e) {
            if (SHOW_DEBUG_CONSOLE) {
                wprintf(L"Backup failed: %hs\n", e.what());
            }
        }
    } else {
        if (SHOW_DEBUG_CONSOLE) {
            wprintf(L"Backup skipped (CREATE_BACKUP = false)\n");
        }
    }

}

typedef BOOL (WINAPI *SetWindowTextW_t)(HWND, LPCWSTR);
SetWindowTextW_t oSetWindowTextW = NULL;
LPCWSTR NEW_TITLE = L"Jar2Exe v2.7.1.1397 Cracked by EagleW4tchBR";

HWND g_mainWnd = NULL;

BOOL WINAPI hkSetWindowTextW(HWND hwnd, LPCWSTR text)
{
    if (hwnd == g_mainWnd) {
        return oSetWindowTextW(hwnd, NEW_TITLE);
    }
    return oSetWindowTextW(hwnd, text);
}

void ForceUpdateTitle()
{
    if (g_mainWnd) {
        SetWindowTextW(g_mainWnd, NEW_TITLE);
    }
}

typedef int (WINAPI *DrawTextW_t)(HDC hDC, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format);
DrawTextW_t oDrawTextW = NULL;

bool g_triggered = false;
const wchar_t* g_target_start = L"Executive file \"";
const wchar_t* g_target_end = L"\" created successfully.";


/*
int WINAPI hkDrawTextW(HDC hDC, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format)
{
    if (lpchText && cchText > 0) {
        if (wcsstr(lpchText, g_target_start) && wcsstr(lpchText, g_target_end)) {
            if (SHOW_DEBUG_CONSOLE) {
                wprintf(L"=== DRAWTEXTW SUCCESS HIT! ***\n");
                wprintf(L"Full text: %.200ls...\n", lpchText);
            }

            const wchar_t* start = wcsstr(lpchText, g_target_start);
            if (start) {
                start += wcslen(g_target_start);
                const wchar_t* end = wcsstr(start, g_target_end);
                if (end) {
                    size_t path_len = end - start;
                    if (path_len > 0 && path_len < 1024) {
                        wchar_t wpath[1025];
                        wcsncpy(wpath, start, path_len);
                        wpath[path_len] = L'\0';

                        char path[1025];
                        wcstombs(path, wpath, 1024);
                        path[1024] = '\0';

                        // Try both: raw path and + ".exe"
                        vector<string> candidates = { string(path), string(path) + ".exe" };

                        string patched_file;
                        bool is_elf = false;

                        for (const auto& candidate : candidates) {
                            ifstream testf(candidate, ios::binary);
                            if (!testf) continue;

                            u8 magic[4] = {0};
                            testf.read((char*)magic, 4);
                            testf.close();

                            if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                                patched_file = candidate;
                                is_elf = true;
                                break;
                            }
                            if (magic[0] == 'M' && magic[1] == 'Z') {
                                patched_file = candidate;
                                is_elf = false;
                                break;
                            }
                        }

                        if (patched_file.empty()) {
                            if (SHOW_DEBUG_CONSOLE) {
                                wprintf(L"*** No ELF/PE file found at: %ls ***\n", wpath);
                            }
                            return oDrawTextW(hDC, lpchText, cchText, lprc, format);
                        }

                        if (SHOW_DEBUG_CONSOLE) {
                            wprintf(L"Detected %s: %hs\n", is_elf ? L"ELF" : L"PE", patched_file.c_str());
                        }

                        try {
                            patch_file(patched_file, DEFAULT_PATCHES, false, false);
                            if (SHOW_DEBUG_CONSOLE) {
                                wprintf(L"*** Patch applied to %hs ***\n", patched_file.c_str());
                            }
                        } catch (const std::exception& e) {
                            if (SHOW_DEBUG_CONSOLE) {
                                wprintf(L"*** Patching failed: %hs ***\n", e.what());
                            }
                        }

                        g_triggered = true;
                    }
                }
            }
        }
    }
    return oDrawTextW(hDC, lpchText, cchText, lprc, format);
}
*/

int WINAPI hkDrawTextW(HDC hDC, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format)
{
    if (lpchText && cchText > 0) {
        if (wcsstr(lpchText, g_target_start) && wcsstr(lpchText, g_target_end)) {
            if (SHOW_DEBUG_CONSOLE) {
                wprintf(L"=== DRAWTEXTW SUCCESS HIT! ***\n");
                wprintf(L"Full text: %.200ls...\n", lpchText);
            }

            const wchar_t* start = wcsstr(lpchText, g_target_start);
            if (start) {
                start += wcslen(g_target_start);
                const wchar_t* end = wcsstr(start, g_target_end);
                if (end) {
                    size_t path_len = end - start;
                    if (path_len > 0 && path_len < 1024) {
                        wchar_t wpath[1025];
                        wcsncpy(wpath, start, path_len);
                        wpath[path_len] = L'\0';

                        char path[1025];
                        wcstombs(path, wpath, 1024);
                        path[1024] = '\0';

                        // === TRY TO PATCH FILE ===
                        vector<string> candidates = { string(path), string(path) + ".exe" };
                        string patched_file;
                        bool is_elf = false;

                        for (const auto& candidate : candidates) {
                            ifstream testf(candidate, ios::binary);
                            if (!testf) continue;

                            u8 magic[4] = {0};
                            testf.read((char*)magic, 4);
                            testf.close();

                            if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                                patched_file = candidate;
                                is_elf = true;
                                break;
                            }
                            if (magic[0] == 'M' && magic[1] == 'Z') {
                                patched_file = candidate;
                                is_elf = false;
                                break;
                            }
                        }

                        if (!patched_file.empty()) {
                            if (SHOW_DEBUG_CONSOLE) {
                                wprintf(L"Detected %s: %hs\n", is_elf ? L"ELF" : L"PE", patched_file.c_str());
                            }
                            try {
                                patch_file(patched_file, DEFAULT_PATCHES, false, false);
                                if (SHOW_DEBUG_CONSOLE) {
                                    wprintf(L"*** Patch applied to %hs ***\n", patched_file.c_str());
                                }
                            } catch (const std::exception& e) {
                                if (SHOW_DEBUG_CONSOLE) {
                                    wprintf(L"*** Patching failed: %hs ***\n", e.what());
                                }
                            }
                        } else {
                            if (SHOW_DEBUG_CONSOLE) {
                                wprintf(L"*** No ELF/PE file found at: %ls ***\n", wpath);
                            }
                        }

                        g_triggered = true;

                        // === NOW MODIFY THE TEXT TO SHOW "CRACKED" ===
                        // We need to create a mutable copy
                        vector<wchar_t> modified_text(lpchText, lpchText + cchText + 1);
                        modified_text[cchText] = L'\0';  // Null-terminate

                        wchar_t* mod_start = wcsstr(modified_text.data(), g_target_end);
                        if (mod_start) {
                            // Replace "created successfully." with "CRACKED successfully."
                            const wchar_t* new_suffix = L" CRACKED successfully.";
                            size_t suffix_len = wcslen(new_suffix);
                            size_t old_suffix_len = wcslen(g_target_end);

                            if (suffix_len <= old_suffix_len) {
                                // Fits in place
                                wcsncpy(mod_start, new_suffix, suffix_len);
                                mod_start[suffix_len] = L'.';  // Keep the dot
                            } else {
                                // Need to grow buffer
                                vector<wchar_t> big_text;
                                big_text.reserve(cchText + suffix_len - old_suffix_len + 1);
                                const wchar_t* prefix = lpchText;
                                const wchar_t* suffix_start = wcsstr(prefix, g_target_end);
                                big_text.insert(big_text.end(), prefix, suffix_start);
                                big_text.insert(big_text.end(), new_suffix, new_suffix + suffix_len);
                                big_text.push_back(L'.');
                                big_text.push_back(L'\0');

                                // Update rectangle to fit longer text
                                DrawTextW(hDC, big_text.data(), -1, lprc, format | DT_CALCRECT);
                                DrawTextW(hDC, big_text.data(), -1, lprc, format);
                                return 0;  // We drew it
                            }
                        }

                        // If small change, draw modified version
                        DrawTextW(hDC, modified_text.data(), -1, lprc, format);
                        return 0;  // We handled drawing
                    }
                }
            }
        }
    }

    // Normal case: pass through
    return oDrawTextW(hDC, lpchText, cchText, lprc, format);
}

void DebugWait()
{
    if (!SHOW_DEBUG_CONSOLE) return;
    AllocConsole();
    SetConsoleTitleW(L"CrackMe Debug Console");
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    wprintf(L"=== Debug Console Started ===\n");
    wprintf(L"Title hook enabled.\n");
    wprintf(L"DrawTextW hook enabled.\n");
    wprintf(L"Run the app and trigger the success condition...\n");
    wprintf(L"Console will stay open. Close app or press Ctrl+C to exit.\n\n");
    while (true) {
        Sleep(5000);
        if (g_triggered) {
            wprintf(L"Success detected! Press any key to close console...\n");
            _getwch();
            FreeConsole();
            return;
        }
    }
}

DWORD WINAPI MainThread(LPVOID)
{
    Sleep(4500);
    HWND hwnd = GetForegroundWindow();
    while (hwnd) {
        wchar_t title[512];
        GetWindowTextW(hwnd, title, 512);
        if (wcsstr(title, L"Jar2Exe")) {
            g_mainWnd = hwnd;
            break;
        }
        hwnd = GetParent(hwnd);
    }
    if (!g_mainWnd) {
        g_mainWnd = GetForegroundWindow();
    }
    MH_Initialize();
    MH_CreateHook((LPVOID)SetWindowTextW, (LPVOID)hkSetWindowTextW, (LPVOID*)&oSetWindowTextW);
    MH_EnableHook((LPVOID)SetWindowTextW);
    ForceUpdateTitle();
    MH_CreateHook((LPVOID)DrawTextW, (LPVOID)hkDrawTextW, (LPVOID*)&oDrawTextW);
    MH_EnableHook((LPVOID)DrawTextW);
    // Wait without console if disabled
    if (SHOW_DEBUG_CONSOLE) {
        DebugWait();
    } else {
        while (!g_triggered) {
            Sleep(1000);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    return TRUE;
}