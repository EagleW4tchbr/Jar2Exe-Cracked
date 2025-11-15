#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <thread>
#define IDI_ICON 1
//
// Config / class-level (file-level) values you can change quickly:
// FUCKING HELL I MISS JAVA
const std::wstring TARGET_PROCESS = L"j2ewiz.exe"; // process name to look for
static std::wstring TARGET_TITLE = L"Thanks For Using it :)"; // <- change this once, reused everywhere
// Setter for convenience if you want to change at runtime
void SetTargetTitle(const std::wstring& newTitle) {
    TARGET_TITLE = newTitle;
}
void CenterTop(HWND hwnd)
{
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int winW = rc.right - rc.left;
    int winH = rc.bottom - rc.top;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int newX = (screenW - winW) / 2;
    int newY = 20; // top margin
    SetWindowPos(
        hwnd, HWND_TOPMOST,
        newX, newY,
        0, 0,
        SWP_NOSIZE | SWP_NOACTIVATE
    );
}
HWND hLabel = nullptr;
COLORREF textColor = RGB(255, 0, 0); // red for waiting
bool blinkState = false;
UINT_PTR timerID = 0;
bool found = false;
// Utility to find process by name
DWORD FindProcessId(const std::wstring &processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;
    DWORD pid = 0;
    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}
std::wstring GetExeDirectory() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        return L"";
    }
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        return fullPath.substr(0, pos + 1);  // Include trailing backslash
    }
    return L"";
}
void ShowThemedMessageBox(HWND hwnd, const std::wstring &text, const std::wstring &title) {
    // Run the message box in a separate thread so UI keeps running
    std::thread([hwnd, text, title]() {
        MessageBoxW(hwnd, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        PostMessage(hwnd, WM_CLOSE, 0, 0); // close after OK
    }).detach();
}
// EnumWindows callback that sets title on top-level windows owned by pid.
// Reads the desired title from TARGET_TITLE.
BOOL CALLBACK EnumWindowsProc_SetTitle(HWND hwnd, LPARAM lParam) {
    DWORD targetPid = static_cast<DWORD>(lParam);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != targetPid) return TRUE; // continue enumerating
    // Optionally only change visible windows; remove check if you want hidden ones too.
    if (!IsWindowVisible(hwnd)) return TRUE;
    SetWindowTextW(hwnd, TARGET_TITLE.c_str());
    return TRUE; // continue
}
// Sets top-level windows owned by pid to the TARGET_TITLE (or a title set earlier by SetTargetTitle)
bool SetWindowsTitleForProcess(DWORD pid) {
    return EnumWindows(EnumWindowsProc_SetTitle, static_cast<LPARAM>(pid)) != 0;
}
// Attach to console (if any) and set console title to TARGET_TITLE
bool SetConsoleTitleOfProcess(DWORD pid) {
    FreeConsole();
    if (!AttachConsole(pid)) {
        return false;
    }
    BOOL ok = SetConsoleTitleW(TARGET_TITLE.c_str());
    FreeConsole();
    return ok != 0;
}
bool InjectDLL(DWORD pid, const std::wstring &dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    // allocate memory in target process
    LPVOID alloc = VirtualAllocEx(hProcess, NULL, (dllPath.size() + 1) * sizeof(wchar_t),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) {
        CloseHandle(hProcess);
        return false;
    }
    // write dll path into target process memory
    WriteProcessMemory(hProcess, alloc, dllPath.c_str(),
                       (dllPath.size() + 1) * sizeof(wchar_t), NULL);
    // load the dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLib =
    (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)loadLib,
                                        alloc, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFont = nullptr;
    static HBRUSH hbrBackground = CreateSolidBrush(RGB(30, 30, 30)); // dark bg
    switch (msg) {
    case WM_CREATE:
        hLabel = CreateWindowW(L"STATIC",
                               (L"WAITING FOR " + TARGET_PROCESS + L"...").c_str(),
                               WS_VISIBLE | WS_CHILD | SS_CENTER,
                               20, 40, 280, 40,
                               hwnd, NULL, NULL, NULL);
        hFont = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            VARIABLE_PITCH, L"Segoe UI");
        SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        timerID = SetTimer(hwnd, 1, 500, NULL); // blink timer
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        SetBkMode(hdcStatic, TRANSPARENT);
        SetTextColor(hdcStatic, textColor);
        return (LRESULT)hbrBackground;
    }
    case WM_TIMER: {
        if (found) break; // stop blink once found
        DWORD pid = FindProcessId(TARGET_PROCESS);
        if (pid) {
            found = true;
            wchar_t buffer[128];
            swprintf_s(buffer, L"FOUND %s (PID %u)", TARGET_PROCESS.c_str(), pid);
            SetWindowTextW(hLabel, buffer);
            textColor = RGB(0, 255, 0); // green
            InvalidateRect(hLabel, NULL, TRUE);
            // Dynamic path to hook_jar2exe.dll in same directory as EXE (no subfolder)
            std::wstring exeDir = GetExeDirectory();
            std::wstring dllPath = exeDir + L"hook_jar2exe.dll";
            // Check if DLL exists
            DWORD fileAttrs = GetFileAttributesW(dllPath.c_str());
            if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
                ShowThemedMessageBox(hwnd, L"DLL not found in EXE directory! Place hook_jar2exe.dll next to the injector.", L"Error");
                break;
            }
            if (InjectDLL(pid, dllPath)) {
                // NEW: Immediately set title from injector for instant effect
                SetWindowsTitleForProcess(pid);
                ShowThemedMessageBox(hwnd, L"DLL injected successfully! Support The Dev and Buy The Original Licence of jar2Exe When Possible <3", L"Success");
            } else {
                ShowThemedMessageBox(hwnd, L"FAILED to inject DLL!", L"Error");
            }
        } else {
            // Blink red/white while waiting
            blinkState = !blinkState;
            textColor = blinkState ? RGB(255, 0, 0) : RGB(255, 255, 255);
            InvalidateRect(hLabel, NULL, TRUE);
        }
        break;
    }
    case WM_DESTROY:
        KillTimer(hwnd, timerID);
        if (hFont) {
            DeleteObject(hFont);
            hFont = nullptr;
        }
        if (hbrBackground) {
            DeleteObject(hbrBackground);
            hbrBackground = nullptr;
        }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"WatcherWindow";
    WNDCLASSEX wc = {}; // Changed to WNDCLASSEX for small icon support
    wc.cbSize = sizeof(WNDCLASSEX); // Required for WNDCLASSEX
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    // NEW: Load icons from resources (before RegisterClass)
    wc.hIcon = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON), IMAGE_ICON, 0, 0,
                                LR_DEFAULTSIZE | LR_DEFAULTCOLOR | LR_SHARED);
    wc.hIconSm = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON), IMAGE_ICON,
                                  GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                  LR_DEFAULTCOLOR | LR_SHARED);
    if (!RegisterClassEx(&wc)) { // Changed to RegisterClassEx
        MessageBoxW(NULL, L"Failed to register window class", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST, // <- ALWAYS ON TOP!
        CLASS_NAME,
        L"Jar2Exe Injector",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 340, 160,
        NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        MessageBoxW(NULL, L"Failed to create window", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    // NEW: Move window to center-top
    CenterTop(hwnd);
    // Example: change the title at runtime (optional)
    // SetTargetTitle(L"MY NEW TITLE");
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}