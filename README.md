# Jar2Exe Crack + DLL Injector

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![Status](https://img.shields.io/badge/status-educational-green)

**Remove the 30-day trial from generated EXE/ELF files** – *Educational / Personal Use Only*
<div align="center">

| ![Jar2Exe Logo](https://www.jar2exe.com/sites/default/files/images/pics/box-shadow-230.png) | <img src="https://vvelitkn.com/assets/images/Malware-Analysis/What-is-DLL-Injection/logo.jpg" width="200" height="200" alt="DLL Injection"> |
|---|---|

</div>

---

## Table of Contents
- [What It Does](#what-it-does)
- [Supported Platforms](#supported-platforms)
- [English Tutorial](#english-tutorial)
- [Tutorial em Português (PT-BR)](#tutorial-em-português-pt-br)
- [How the Crack Works](#how-the-crack-works)
- [Legal & Ethical Note](#legal--ethical-note)
- [Credits](#credits)

---
## DEMO:


https://github.com/user-attachments/assets/e1c0fe72-bcbc-467d-bf8f-4ee56378a979



## What It Does
- **Cracks** `j2ewiz.exe` (v2.7) to bypass registration.
- **Injects** `hook_jar2exe.dll` via **MinHook**.
- **Removes** the trial checksum **and** binary integrity protection from generated files.
- Produces **fully unrestricted** `.exe` (Windows) and `.elf` (Linux) files – **no 30-day trial**.

---

## Supported Platforms
| Platform | Tested | Notes |
|----------|--------|-------|
| Windows 10 x64 | ✅ | Full support |
| Linux x64      | ✅ | Full support |
| macOS          | ❌ | Generated binaries remain trial-limited (no macOS test environment) |

---

## English Tutorial

### Setup
1. **Download** Jar2Exe from the official site:  
   <https://www.jar2exe.com/downloads> → *Jar2Exe_x86.zip (7.6 MB, V2.7 Green Package Without Install)*.
2. **Extract** `Jar2Exe_x86.zip` to a folder of your choice.
3. **Replace** the original `j2ewiz.exe` with the cracked version from the **`Crack`** folder.
4. **Copy** **all files** from the **`Injector`** folder into the same directory (the one from step 2).

### Run
1. Launch **`Jar2exe_Injector.exe`**.
2. Run the **cracked** `j2ewiz.exe`.  
   *Order does not matter – both must be running simultaneously.*
3. When the **MessageBox** “Ready” appears, the hook is active.

You can now generate **unrestricted** EXE/ELF files.

---

## Tutorial em Português (PT-BR)

### Configuração
1. **Baixe** o Jar2Exe em:  
   <https://www.jar2exe.com/downloads> → *Jar2Exe_x86.zip (7.6 MB, V2.7 Pacote Verde Sem Instalação)*.
2. **Extraia** o `Jar2Exe_x86.zip` para uma pasta.
3. **Substitua** o `j2ewiz.exe` original pelo arquivo crackeado da pasta **`Crack`**.
4. **Copie** **todos os arquivos** da pasta **`Injector`** para o mesmo diretório (passo 2).

### Execução
1. Execute **`Jar2exe_Injector.exe`**.
2. Execute o `j2ewiz.exe` **crackeado**.  
   *A ordem não importa – ambos precisam estar em execução ao mesmo tempo.*
3. Quando a **MessageBox** “Pronto” aparecer, o hook está ativo.

Agora você pode gerar arquivos **EXE/ELF sem limitação de 30 dias**.

Vai Brasil Chupa Meu OVO STF E ABIN <3

---

## How The Crack Works
#### Linux ELF Patches

    0x001580d6  JMP 0x001580dc   ; Skip trial expiration check #1
    0x001581da  JMP 0x001581e0   ; Skip trial expiration check #2


#### Windows EXE Patches

    0x004164c9  JMP <target>     ; Skip trial checksum validation
    0x004161eb  JMP <target>     ; Skip binary integrity enforcement

> These jumps **bypass time‑based trial enforcement** in the generated
> executable, making it **fully unrestricted**.
> 
> **Result:** Fully unrestricted binaries for Windows and Linux.
> 
> **macOS binaries** are **not patched** (no test machine).
## Binary Patch Analysis – Unlocking All Features

The Core Of The Crack Consists Of **Static Binary Patches** Applied To j2ewiz.exe (v2.7) Using **Ghidra**.

 1. **Disable Registration Flag:**

  

  

>     ADDRESS:     0x004039DD
>     
>     ORIGINAL:    MOV EBP, 0x1          ; falsely sets "registered"
>                  004039DD  BD 01 00 00 00
>     
>     PATCH:       MOV EBP, 0x0          ; forces "unregistered" → unlocks UI
>                  004039DD  BD 00 00 00 00


2. **Bypass Trial Time Check #1:**

>     ADDRESS:     0x004049FB
>     
>     ORIGINAL:
>         004049FB  89 0D 14 95 48 00   MOV [EDIT_TIME_CHECK_TRIAL_2], ECX
>         00404A01  FF 15 44 19 47 00   CALL [->MSVCRT.DLL::time]
>     
>     PATCH:
>         004049FB  C7 05 14 95 48 00   MOV [EDIT_TIME_CHECK_TRIAL_2], 0x1
>                   01 00 00 00
>         00404A05  90                  NOP
>         00404A06  90                  NOP

3. **Bypass Trial Time Check #2:**

>     ADDRESS:     0x0040582E
>     
>     ORIGINAL:
>         0040582E  89 0D 14 95 48 00   MOV [EDIT_TIME_CHECK_TRIAL_2], ECX
>         00405834  FF 15 44 19 47 00   CALL [->MSVCRT.DLL::time]
>     
>     PATCH:
>         0040582E  C7 05 14 95 48 00   MOV [EDIT_TIME_CHECK_TRIAL_2], 0x1
>                   01 00 00 00
>         00405838  90                  NOP
>         00405839  90                  NOP

4. **Remove Trial UI Lock:**

>     ADDRESS:     0x00421EF3
>     
>     ORIGINAL:    JZ  LAB_00421F30       ; jump if trial → hide full features
>                  00421EF3  74 3B
>     
>     PATCH:       JMP EDIT_REMOVE_TRIAL_RADIO
>                  00421EF3  EB 3B

***

> **Note:** These Patches Were Discovered Over **3 weeks** Of Reverse Engineering. Edge‑cases May Still Exist.
---

## Legal & Ethical Note
> This project is **strictly for educational purposes** – learning reverse engineering, DLL injection, and binary patching.  
> It is **not** intended for piracy, commercial use, or distribution of cracked software.

**If you like Jar2Exe, please purchase a license:**  
[https://www.jar2exe.com/purchase](https://www.jar2exe.com/purchase)

---

## Credits
| Component | Author / Source |
|-----------|-----------------|
| **Original Application** | [Jar2Exe](https://www.jar2exe.com/) © RegExLab.com (2007–2023) |
| **Reverse Engineering & Patching Software** | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) – NSA's SRE Toolkit |
| **Crack,patching, DLL Injector & Hook Logic** | [EagleW4tchBR](https://github.com/EagleW4tchBR) |
| **DLL Injection Library** | [MinHook](https://github.com/TsudaKageyu/minhook) |
| **DLL Compiler** | [mingw](https://github.com/brechtsanders/winlibs_mingw/) - [I Used The 32 Version](https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-13.0.0-msvcrt-r3/winlibs-i686-posix-dwarf-gcc-15.2.0-mingw-w64msvcrt-13.0.0-r3.zip)|
---

**Use at your own risk.**  
DLL injection may trigger antivirus software. Scan all files with [VirusTotal](https://www.virustotal.com) before use.

*Feel free to redistribute the source under the MIT license.*

---

*Thank you for respecting software developers!*



