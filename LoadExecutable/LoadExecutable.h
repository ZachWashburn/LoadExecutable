#pragma once
namespace LoadExe
{
	
	typedef int (__stdcall* fnFarProceducre_t)();
	typedef unsigned long (__stdcall* fnLoadLibraryA_t)(const char* lpLibFileName);
	typedef void (__cdecl* fnexit_t)(int _Code);
	typedef void (__cdecl* fn_cexit_t)(void);
	typedef unsigned long (__cdecl* fnGetCurrentProcess_t)();
	typedef bool(__stdcall* fnVirtualProtect_t)(void* lpAddress, size_t dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
	typedef fnFarProceducre_t (__stdcall*fnGetProcAddress_t)(unsigned long hModule, char* lpProcName);

	

	void INIT_LoadExecutable(
		void* pfnLoadLibraryA,
		void* pfnGetCurrentProcess,
		void* pfnVirtualProtect,
		void* pfnGetProcAddress, 
		bool bThrowStdExceptionOnExitProcess = false
	);

	unsigned long long LoadExecutable(const char* szExecutable);
	void* GetEntryFunction(unsigned long hModule);

	// unfinished : 
	void* __stdcall SwapExportFunctionAddress(unsigned long hModule, char* FunctionName, void* SwappedFunction);
	void __stdcall SwapImportFunctionAddress(unsigned long hModule, char* FunctionName, void* SwappedFunction);


}
