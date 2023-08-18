// MiniProcExpl.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "MiniProcExpl.h"
#include "psapi.h"
#include "heapapi.h"
#include "handleapi.h"
#include "fileapi.h"
#include "bcrypt.h"
#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>
#include <functional>

#pragma comment(lib, "bcrypt.lib")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain( HINSTANCE hInstance,
                      HINSTANCE hPrevInstance,
                      LPWSTR    lpCmdLine,
                      int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_MINIPROCEXPL, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MINIPROCEXPL));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MINIPROCEXPL));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_MINIPROCEXPL);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_TILEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

typedef struct Results {
    // DLL information
    INT moduleNum;
    LPMODULEINFO* lpminfo;
    
    // File information
    LPWSTR imagename;
    LPWSTR imagepath;
    DWORD bytesize;
    const CHAR* algorithm;
    PBYTE hash;
    // children files? log location? 

    // Process Info
    DWORD pid; 
    PROCESS_MEMORY_COUNTERS* pmc;

    // HEAP Info
    //HEAP_SUMMARY hs;

    // Thread Info

    // Handle Info
    DWORD handleNum;
    LPDWORD* handleFlags;

    // IAT/EAT

    // access token information
    TOKEN_INFORMATION_CLASS tic;
    
};


// what to return, 
Results CALLBACK ProcEnumeration(DWORD pid)
{
    // initialize structs for get proc info function
    auto pr_info = PROCESS_INFORMATION_CLASS{};
    auto pfo = PROCESS_INFORMATION{};
    // open a handle to the process, should work unless explorer or main system processes
    HANDLE hproc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    // open process information
    BOOL check = GetProcessInformation(hproc, pr_info, &pfo, sizeof(pfo));
    if (check != TRUE) {
        // we may need to add exceptions for certain processes that are unnable to access.
        
    }

    PROCESS_MEMORY_COUNTERS pmc;
    BOOL check = GetProcessMemoryInfo(hproc, &pmc, sizeof(pmc));
    if (check != TRUE) {

    }
    LPWSTR filename;
    DWORD str_length = GetProcessImageFileName(hproc, filename, sizeof(filename));
    LPWSTR buffer;
    LPWSTR* fname;
    DWORD bufferLength = GetFullPathName(filename, sizeof(filename), buffer, fname);

    PVOID buffer;
    BOOL check = QueryWorkingSet(hproc, buffer, sizeof(buffer));
    if (check != TRUE) {

    }
    HMODULE modules;
    DWORD cb; 
    BOOL check = EnumProcessModules(hproc, &modules, sizeof(modules), &cb);
    if (!check) {

    }
    LPMODULEINFO* mi;
    // want to loop the modules with GetModuleInformation()
    
    
    PDWORD handlecount;
    BOOL check = GetProcessHandleCount(hproc, handlecount);
    if (!check) {

    };
    LPDWORD lpdwFlags;
    BOOL check = GetHandleInformation(hproc, lpdwFlags);
    // need some way for me to grab a file hash of file in file system
    
    const CHAR* alg = "SHA256";
    
    HANDLE hfile;
    LPDWORD fsize;
    DWORD check = GetFileSize(hfile, fsize);
    HANDLE thandle;
    BOOL check = OpenProcessToken(hproc, READ_CONTROL, &thandle);
    if (!check) {

    };
    TOKEN_INFORMATION_CLASS tic;
    LPVOID f;

    BOOL check = GetTokenInformation(thandle, tic, f, sizeof(f), NULL);
    if (!check) {

    };

    // okay so we made a custom sha function with bcrypt, now we need to open the image we got and read byte by byte.
    auto openfilestruct = new OFSTRUCT;
    HFILE filehandle = OpenFile((LPCSTR)filename, openfilestruct, 0x00000000);
    if (!filehandle) {

    };
    LPVOID buff;
    BOOL check = ReadFile((HANDLE)filehandle, buff, 1000000, NULL, NULL);
    if (!check) {

    };
    PBYTE hash = sha256((BYTE*)buff);
 
    Results res = Results{ sizeof(modules),mi , filename, buffer, *fsize, alg, hash, pid, &pmc, *handlecount,  };
    CloseHandle(hproc);
    CloseHandle(thandle);

    return Results{ NULL, NULL, NULL, NULL, NULL };
}
void ReportError(_In_ DWORD dwErrCode)
{
    wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
}

PBYTE CALLBACK sha256(BYTE* fileBytes) {
    NTSTATUS    Status;

    BCRYPT_ALG_HANDLE   AlgHandle = NULL;
    BCRYPT_HASH_HANDLE  HashHandle = NULL;

    PBYTE   Hash = NULL;
    DWORD   HashLength = 256;
    DWORD   ResultLength = 0;

    //
    // Open an algorithm handle
    // This sample passes BCRYPT_HASH_REUSABLE_FLAG with BCryptAlgorithmProvider(...) to load a provider which supports reusable hash
    //

    Status = BCryptOpenAlgorithmProvider(
        &AlgHandle,                 // Alg Handle pointer
        BCRYPT_SHA256_ALGORITHM,    // Cryptographic Algorithm name (null terminated unicode string)
        NULL,                       // Provider name; if null, the default provider is loaded
        BCRYPT_HASH_REUSABLE_FLAG); // Flags; Loads a provider which supports reusable hash
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
        goto cleanup;
    }

    //
    // Obtain the length of the hash
    //

    Status = BCryptGetProperty(
        AlgHandle,                  // Handle to a CNG object
        BCRYPT_HASH_LENGTH,         // Property name (null terminated unicode string)
        (PBYTE)&HashLength,         // Address of the output buffer which recieves the property value
        sizeof(HashLength),         // Size of the buffer in bytes
        &ResultLength,              // Number of bytes that were copied into the buffer
        0);                         // Flags
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
        goto cleanup;
    }

    //
    // Allocate the hash buffer on the heap
    //

    Hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
    if (NULL == Hash)
    {
        Status = STATUS_NO_MEMORY;
        ReportError(Status);
        goto cleanup;
    }

    //
    // Create a hash handle
    //

    Status = BCryptCreateHash(
        AlgHandle,                  // Handle to an algorithm provider                 
        &HashHandle,                // A pointer to a hash handle - can be a hash or hmac object
        NULL,                       // Pointer to the buffer that recieves the hash/hmac object
        0,                          // Size of the buffer in bytes
        NULL,                       // A pointer to a key to use for the hash or MAC
        0,                          // Size of the key in bytes
        0);                         // Flags
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
        goto cleanup;
    }

    //
    // Hash the message(s)
    // More than one message can be hashed by calling BCryptHashData 
    //
    PBYTE Message;
    Status = BCryptHashData(
        HashHandle,                 // Handle to the hash or MAC object
        (PBYTE)Message,             // A pointer to a buffer that contains the data to hash
        sizeof(Message),           // Size of the buffer in bytes
        0);                         // Flags
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
        goto cleanup;
    }

    //
    // Obtain the hash of the message(s) into the hash buffer
    //

    Status = BCryptFinishHash(
        HashHandle,                 // Handle to the hash or MAC object
        Hash,                       // A pointer to a buffer that receives the hash or MAC value
        HashLength,                 // Size of the buffer in bytes
        0);                         // Flags
    if (!NT_SUCCESS(Status))
    {
        ReportError(Status);
        goto cleanup;
    }

    Status = STATUS_SUCCESS;
    return Hash;
cleanup:

    if (NULL != Hash)
    {
        HeapFree(GetProcessHeap(), 0, Hash);
    }

    if (NULL != HashHandle)
    {
        BCryptDestroyHash(HashHandle);                             // Handle to hash/MAC object which needs to be destroyed
    }

    if (NULL != AlgHandle)
    {
        BCryptCloseAlgorithmProvider(
            AlgHandle,                  // Handle to the algorithm provider which needs to be closed
            0);                         // Flags
    }
}

// I want this to be an element up at the top of the window that allows the user to select the scan and initiate it on processes.
VOID MainProcAnalysis() {
 
    DWORD* pids;
    BOOL check = EnumProcesses(pids, sizeof(pids), NULL);
    double pid_length = sizeof(pids[0]) / sizeof(pids);
    if (pid_length == 1) {
        // need to write an err dialog box

    }
    else {
        // this should be functions to fetch lots of other data on the process and such at run time, including heap memory, working set, priv working set, threads, handles, etc.
        // process shit
        Results* res_arr;
        for (int i = 0; i < pid_length; i++) {
            DWORD pid = pids[i];
            // ps api functions
            Results res = ProcEnumeration(pid);
            // do drivers next, then filesystem, then 
            res_arr[i] = res;


        };

    }
}