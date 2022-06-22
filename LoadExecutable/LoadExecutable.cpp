// LoadExecutable.cpp : Defines the functions for the static library.
//
#include <Windows.h>
#include <cstdio>
#include <exception>
#include "LoadExecutable.h"

LoadExe::fnLoadLibraryA_t g_pfnLoadLibrary;
LoadExe::fnexit_t g_pfnexithk;
LoadExe::fn_cexit_t g_pfncexithk;
LoadExe::fnGetCurrentProcess_t g_pfnGetCurrentProcess;
LoadExe::fnVirtualProtect_t g_pfnVirtualProtect;
LoadExe::fnGetProcAddress_t g_pfnGetProcAddress;
bool g_bExcept;

PVOID WINAPI ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader);
PVOID WINAPI ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader);
PVOID WINAPI ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader);
PVOID WINAPI ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders);
LPCVOID WINAPI ImageDirectoryEntryToDataEx(const PVOID Base, const BOOLEAN MappedAsImage, const USHORT DirectoryEntry, ULONG* Size);
LPCVOID WINAPI ImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size);
void ParseIAT(HINSTANCE h);

void LoadExe::INIT_LoadExecutable(
	void* pfnLoadLibraryA,
	void* pfnGetCurrentProcess,
	void* pfnVirtualProtect,
	void* pfnGetProcAddress,
	bool bThrowStdExceptionOnExitProcess
)
{
	g_pfnLoadLibrary = (decltype(g_pfnLoadLibrary))pfnLoadLibraryA;
	//g_pfnexithk = (decltype(g_pfnexithk))pfnexithk;
	//g_pfncexithk = (decltype(g_pfncexithk))pfncexithk;
	g_pfnGetCurrentProcess = (decltype(g_pfnGetCurrentProcess))g_pfnGetCurrentProcess;
	g_pfnVirtualProtect = (decltype(g_pfnVirtualProtect))pfnVirtualProtect;
	g_pfnGetProcAddress = (decltype(g_pfnGetProcAddress))pfnGetProcAddress;
	g_bExcept = bThrowStdExceptionOnExitProcess;
}

unsigned long long LoadExe::LoadExecutable(
	const char* szExecutable
)
{
	unsigned long long hHandle = g_pfnLoadLibrary(szExecutable);

	if (!hHandle)
		return hHandle;

	ParseIAT((HINSTANCE)hHandle);

	return hHandle;
}


// http://www.rohitab.com/discuss/topic/40594-parsing-pe-export-table/
/*
		Parameters:

		DllName - The DLL name that contain the function being resolved.

		FunctionName - The name of function to resolve.

		LoadDll - If set, the function calls the LoadLibrary function to load the DLL. Otherwise, the function calls the GetModuleHandle function to find the DLL.

*/
void* LoadExe::GetEntryFunction(unsigned long hModule)
{
	IMAGE_DOS_HEADER* dos_head = (IMAGE_DOS_HEADER*)(hModule);
	IMAGE_NT_HEADERS* nt_head = (IMAGE_NT_HEADERS*)((char*)hModule + dos_head->e_lfanew);
	return (char*)hModule + nt_head->OptionalHeader.AddressOfEntryPoint;
}

void* __stdcall LoadExe::SwapExportFunctionAddress(unsigned long hModule, char* FunctionName, void* SwappedFunction)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;
	PDWORD Address, Name;
	PWORD Ordinal;
	DWORD i;

	if (!hModule)
	{
		return NULL;
	}

	pIDH = (PIMAGE_DOS_HEADER)hModule;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return NULL;
	}

	pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
	Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);

	Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

	for (i = 0; i < pIED->AddressOfFunctions; i++)
	{
		if (!strcmp(FunctionName, (char*)hModule + Name[i]))
		{	
			Address[Ordinal[i]] = &Address[Ordinal[i]] - SwappedFunction;
			return (PVOID)((LPBYTE)hModule + Address[Ordinal[i]]);
		}
	}

	return NULL;
}

DWORD FileOffsetToRVA(IMAGE_NT_HEADERS32* pNtHdr, DWORD dwOffset)
{
	int i;
	WORD wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;

	pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
	wSections = pNtHdr->FileHeader.NumberOfSections;

	for (i = 0; i < wSections; i++) {
		if (pSectionHdr->PointerToRawData <= dwOffset)
			if ((pSectionHdr->PointerToRawData + pSectionHdr->SizeOfRawData) > dwOffset) {
				dwOffset -= pSectionHdr->PointerToRawData;
				dwOffset += pSectionHdr->VirtualAddress;

				return (dwOffset);
			}

		pSectionHdr++;
	}

	return (-1);
}

void __stdcall LoadExe::SwapImportFunctionAddress(unsigned long hModule, char* FunctionName, void* SwappedFunction)
{

	DWORD ulsize = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData((PVOID)hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
	if (!pImportDesc)
		return;

	// Loop names
	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)hModule + pImportDesc->Name);
		if (!pszModName)
			break;

		HINSTANCE hImportDLL = (HINSTANCE)g_pfnLoadLibrary(pszModName);
		if (!hImportDLL)
		{
			// ... (error)
		}

		// Get caller's import address table (IAT) for the callee's functions
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			((PBYTE)hModule + pImportDesc->FirstThunk);

		// Replace current function address with new function address
		for (; pThunk->u1.Function; pThunk++)
		{
			FARPROC pfnNew = 0;
			size_t rva = 0;
#ifdef _WIN64
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
#else
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
#endif
			{
				// Ordinal
#ifdef _WIN64
				size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);
#else
				size_t ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
#endif

				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;

				char fe[100] = { 0 };
				sprintf_s(fe, 100, "#%u", ord);
				pfnNew = g_pfnGetProcAddress((unsigned long)hImportDLL, (char*)ord);
				if (!pfnNew)
				{
					// ... (error)
				}
			}
			else
			{
				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;
				PSTR fName = (PSTR)hModule;
				fName += pThunk->u1.Function;
				fName += 2;
				if (!fName)
					break;
				pfnNew = g_pfnGetProcAddress((unsigned long)hImportDLL, fName);
				if (!pfnNew)
				{
					// ... (error)
				}
			}

			// Patch it now...
			DWORD dwOldProtect;
			g_pfnVirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect);
			//memcpy((LPVOID*)rva, &pfnNew, sizeof(pfnNew));

			*(LPVOID*)rva = pfnNew;
			g_pfnVirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect);

#if 0
			auto hp = g_pfnGetCurrentProcess();
			if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError()))
			{
				DWORD dwOldProtect;
				if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect))
				{
					if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL))
					{
						// ... (error)
					}
					if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect))
					{
						// ... (error)
					}
				}
			}
#endif
		}
	}
}


// as per :
// https://www.codeproject.com/Articles/1045674/Load-EXE-as-DLL-Mission-Possible
void ParseIAT(HINSTANCE h)
{
	// Find the IAT size
	DWORD ulsize = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
	if (!pImportDesc)
		return;

	// Loop names
	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
		if (!pszModName)
			break;

		HINSTANCE hImportDLL = (HINSTANCE)g_pfnLoadLibrary(pszModName);
		if (!hImportDLL)
		{
			// ... (error)
		}

		// Get caller's import address table (IAT) for the callee's functions
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			((PBYTE)h + pImportDesc->FirstThunk);

		// Replace current function address with new function address
		for (; pThunk->u1.Function; pThunk++)
		{
			FARPROC pfnNew = 0;
			size_t rva = 0;
#ifdef _WIN64
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
#else
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
#endif
			{
				// Ordinal
#ifdef _WIN64
				size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);
#else
				size_t ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
#endif

				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;

				char fe[100] = { 0 };
				sprintf_s(fe, 100, "#%u", ord);
				pfnNew = g_pfnGetProcAddress((unsigned long)hImportDLL, (char*)ord);
				if (!pfnNew)
				{
					// ... (error)
				}
			}
			else
			{
				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;
				PSTR fName = (PSTR)h;
				fName += pThunk->u1.Function;
				fName += 2;
				if (!fName)
					break;
				pfnNew = g_pfnGetProcAddress((unsigned long)hImportDLL, fName);
				if (!pfnNew)
				{
					// ... (error)
				}
			}

			// Patch it now...
			DWORD dwOldProtect;
			g_pfnVirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect);
			//memcpy((LPVOID*)rva, &pfnNew, sizeof(pfnNew));
			*(LPVOID*)rva = pfnNew;
			g_pfnVirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect);

#if 0
			auto hp = g_pfnGetCurrentProcess();
			if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError()))
			{
				DWORD dwOldProtect;
				if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect))
				{
					if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL))
					{
						// ... (error)
					}
					if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect))
					{
						// ... (error)
					}
				}
			}
#endif
		}
	}
}



// https://github.com/Speedi13/ROP-COMPILER/blob/master/RopCompiler/dbghelp.cpp
//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageDirectoryEntryToDataEx
//////////////////////////////////////////////////////////////////////////////////////////////////
PVOID WINAPI ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader)
{
	*(ULONG*)Size = NULL;

	if (!DataDirectory->VirtualAddress || !DataDirectory->Size || !SizeOfHeaders)
		return nullptr;

	*(ULONG*)Size = DataDirectory->Size;
	if (MappedAsImage || DataDirectory->VirtualAddress < SizeOfHeaders)
		return (char*)Base + DataDirectory->VirtualAddress;

	WORD SizeOfOptionalHeader = ImageFileHeader->SizeOfOptionalHeader;
	WORD NumberOfSections = ImageFileHeader->NumberOfSections;
	if (!NumberOfSections || !SizeOfOptionalHeader)
		return nullptr;

	IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ImageOptionalHeader + SizeOfOptionalHeader);
	for (DWORD i = 0; i < NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSectionHeader = &pSectionHeaders[i];
		if ((DataDirectory->VirtualAddress >= pSectionHeader->VirtualAddress) &&
			(DataDirectory->VirtualAddress < (pSectionHeader->SizeOfRawData + pSectionHeader->VirtualAddress)))
		{
			return (char*)Base + (DataDirectory->VirtualAddress - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
		}
	}
	return nullptr;
}
PVOID WINAPI ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader)
{
	*(ULONG*)Size = NULL;

	if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if (!DataDirectory->VirtualAddress || !DataDirectory->Size)
		return nullptr;

	return ImageDirectoryEntryToDataInternal(Base,
		MappedAsImage,
		Size,
		ImageOptionalHeader->SizeOfHeaders,
		DataDirectory,
		ImageFileHeader,
		ImageOptionalHeader);
}
PVOID WINAPI ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader)
{
	*(ULONG*)Size = NULL;

	if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if (!DataDirectory->VirtualAddress || !DataDirectory->Size)
		return nullptr;

	return ImageDirectoryEntryToDataInternal(Base,
		MappedAsImage,
		Size,
		ImageOptionalHeader->SizeOfHeaders,
		DataDirectory,
		ImageFileHeader,
		ImageOptionalHeader);
}
PVOID WINAPI ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders)
{
	UNREFERENCED_PARAMETER(HeaderMagic);

	*(ULONG*)Size = NULL;

	if (ImageFileHeader->NumberOfSections <= 0u || !ImageFileHeader->SizeOfOptionalHeader)
		return nullptr;

	IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ImageRomHeaders + ImageFileHeader->SizeOfOptionalHeader);

	WORD j = 0;
	for (; j < ImageFileHeader->NumberOfSections; j++, pSectionHeader++)
	{
		if (DirectoryEntry == 3 && _stricmp((char*)pSectionHeader->Name, ".pdata") == NULL)
			break;
		if (DirectoryEntry == 6 && _stricmp((char*)pSectionHeader->Name, ".rdata") == NULL)
		{
			*(ULONG*)Size = NULL;
			for (BYTE* i = (BYTE*)Base + pSectionHeader->PointerToRawData + 0xC; *(DWORD*)i; i += 0x1C)
				*Size += 0x1C;
			break;
		}
	}
	if (j >= ImageFileHeader->NumberOfSections)
		return nullptr;

	return (char*)Base + pSectionHeader->PointerToRawData;
}



/// <summary>
/// Locates a directory entry within the image header and returns the address of the data for the directory entry
/// </summary>
/// <param name="Base">The base address of the image or data file</param>
/// <param name="MappedAsImage">If the flag is TRUE, the file is mapped by the system as an image. If this flag is FALSE, the file is mapped as a data file by the MapViewOfFile / ReadFile function</param>
/// <param name="DirectoryEntry">The directory entry to be located</param>
/// <param name="Size">A pointer to a variable that receives the size of the data for the directory entry that is located</param>
/// <returns>If the function succeeds, the return value is a pointer to the data for the directory entry</returns>
LPCVOID WINAPI ImageDirectoryEntryToDataEx(const PVOID Base, const BOOLEAN MappedAsImage, const USHORT DirectoryEntry, ULONG* Size)
{
	*(ULONG*)Size = NULL;

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)Base;
	if (!pDosHeader)
		return nullptr;

	IMAGE_FILE_HEADER* ImageFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* ImageOptionalHeader = nullptr;

	LONG NtHeaderFileOffset = pDosHeader->e_lfanew;
	IMAGE_NT_HEADERS* ImageNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + NtHeaderFileOffset);

	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE
		&& NtHeaderFileOffset > 0
		&& NtHeaderFileOffset < 0x10000000u
		&& ImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		ImageFileHeader = &ImageNtHeader->FileHeader;
		ImageOptionalHeader = &ImageNtHeader->OptionalHeader;
	}
	else
	{
		ImageFileHeader = (IMAGE_FILE_HEADER*)Base;
		ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)Base + 0x14);
	}
	switch (ImageOptionalHeader->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		return ImageDirectoryEntryToData32(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_OPTIONAL_HEADER32*)ImageOptionalHeader);
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		return ImageDirectoryEntryToData64(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_OPTIONAL_HEADER64*)ImageOptionalHeader);
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		return ImageDirectoryEntryToDataRom(
			Base,
			IMAGE_ROM_OPTIONAL_HDR_MAGIC,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			(IMAGE_ROM_OPTIONAL_HEADER*)ImageOptionalHeader);
	}
	return nullptr;
}

LPCVOID WINAPI ImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size)
{
	return ImageDirectoryEntryToDataEx(Base, MappedAsImage, DirectoryEntry, Size);
}





