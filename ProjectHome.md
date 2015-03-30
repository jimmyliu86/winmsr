# Purpose #
WinMSR is a Windows 64-bits driver which provides access to the cpuid instruction and the msr registers in the processor ring 0.

The example below returns the temperature of the Intel i7 Processor Cores.

# Open Source IDE #
  * [GCC MinGW 64-bit Compiler](http://sourceforge.net/projects/tdm-gcc)
  * [Code::Blocks standalone version](http://www.codeblocks.org)
# Tools #
  * [DebugView](http://technet.microsoft.com/en-us/sysinternals/bb896647)
# Source Code #
The kernel driver source code.
## driver.c ##
```
#include <ddk/wdm.h>
#include <stdio.h>

#define IA32_THERM_STATUS               0x19c
#define MSR_TEMPERATURE_TARGET          0x1a2

struct
{
	struct
	{
		unsigned char Chr[4];
	} AX, BX, CX, DX;
} Brand;

typedef struct
{
	union
	{
		struct
		{
			unsigned int
				StatusBit       :  1-0,
				StatusLog       :  2-1,
				PROCHOT         :  3-2,
				PROCHOTLog      :  4-3,
				CriticalTemp    :  5-4,
				CriticalTempLog :  6-5,
				Threshold1      :  7-6,
				Threshold1Log   :  8-7,
				Threshold2      :  9-8,
				Threshold2Log   : 10-9,
				PowerLimit      : 11-10,
				PowerLimitLog   : 12-11,
				ReservedBits1   : 16-12,
				DTS             : 23-16,
				ReservedBits2   : 27-23,
				Resolution      : 31-27,
				ReadingValid    : 32-31;
		};
			unsigned int Lo     : 32-0;
	};
			unsigned int Hi     : 32-0;
} THERM_STATUS;

typedef struct
{
	union
	{
		struct
		{
				unsigned int
				ReservedBits1   : 16-0,
				Target          : 24-16,
				ReservedBits2   : 32-24;
		};
				unsigned int Lo : 32-0;
	};
				unsigned int Hi : 32-0;
} TJMAX;

typedef struct
{
		int				cpu;
		HANDLE			TID;

		int				Temp;
		TJMAX			TjMax;
		THERM_STATUS	ThermStat;
} CORE;

CORE Core[64];

NTSTATUS NTAPI DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	return STATUS_SUCCESS;
}

VOID NTAPI DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("WinMSR Unload\n");
	return;
}


VOID ThreadEntry(IN PVOID pArg)
{
	CORE *pCore=(CORE *) pArg;

	KAFFINITY AllCoreBitmap=KeQueryActiveProcessors();
	KAFFINITY ThisCoreBitmap=AllCoreBitmap & (1 << pCore->cpu);
	KeSetSystemAffinityThreadEx(ThisCoreBitmap);

	__asm__ volatile
	(
		"rdmsr ;"
		: "=a" (pCore->TjMax.Lo),
		  "=d" (pCore->TjMax.Hi)
		: "c" (MSR_TEMPERATURE_TARGET)
	);

	__asm__ volatile
	(
		"rdmsr ;"
		: "=a" (pCore->ThermStat.Lo),
		  "=d" (pCore->ThermStat.Hi)
		: "c" (IA32_THERM_STATUS)
	);

	pCore->Temp=pCore->TjMax.Target - pCore->ThermStat.DTS;

	char  DbgStr[32];
	sprintf(DbgStr, "WinMSR: Core(%02d) @ %d°C\n", pCore->cpu, pCore->Temp);
	DbgPrint(DbgStr);
}


NTSTATUS NTAPI DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnload;

	char tmpString[48+1]={0x20}, BrandString[48+1];
	int ix=0, jx=0, px=0;
	for(ix=0; ix<3; ix++)
	{
		__asm__ volatile
		(
			"cpuid ;"
			: "=a"  (Brand.AX),
			  "=b"  (Brand.BX),
			  "=c"  (Brand.CX),
			  "=d"  (Brand.DX)
			: "a"   (0x80000002 + ix)
		);
		for(jx=0; jx<4; jx++, px++)
			tmpString[px]=Brand.AX.Chr[jx];
		for(jx=0; jx<4; jx++, px++)
			tmpString[px]=Brand.BX.Chr[jx];
		for(jx=0; jx<4; jx++, px++)
			tmpString[px]=Brand.CX.Chr[jx];
		for(jx=0; jx<4; jx++, px++)
			tmpString[px]=Brand.DX.Chr[jx];
	}
	for(ix=jx=0; jx < px; jx++)
		if(!(tmpString[jx] == 0x20 && tmpString[jx+1] == 0x20))
			BrandString[ix++]=tmpString[jx];

	DbgPrint(BrandString);

	int cpu;
	for(cpu=0; cpu < KeQueryActiveProcessorCount(NULL); cpu++)
	{
		Core[cpu].cpu=cpu;
		PsCreateSystemThread(&Core[cpu].TID, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE) ThreadEntry, (PVOID) &Core[cpu]);
	}
	return STATUS_SUCCESS;
}
```
## WinMSR.cbp ##
The Code::Blocks project file.
```
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<CodeBlocks_project_file> 
        <FileVersion major="1" minor="6" /> 
        <Project> 
                <Option title="WinMSR" /> 
                <Option pch_mode="2" /> 
                <Option compiler="gcc" /> 
                <Build> 
                        <Target title="Release"> 
                                <Option output="bin/Release/WinMSR" prefix_auto="1" extension_auto="1" /> 
                                <Option working_dir="" /> 
                                <Option object_output="obj/Release/" /> 
                                <Option type="5" /> 
                                <Option compiler="gcc" /> 
                                <Compiler> 
                                        <Add option="-O2" /> 
                                </Compiler> 
                                <Linker> 
                                        <Add option="-s" /> 
                                </Linker> 
                        </Target> 
                </Build> 
                <Compiler> 
                        <Add option="-Wall" /> 
                        <Add directory="C:/Program Files/TDM-GCC-64/x86_64-w64-mingw32/include/ddk" /> 
                </Compiler> 
                <Linker> 
                        <Add option="-nostartfiles" /> 
                        <Add option="-Wl,--nostdlib" /> 
                        <Add option="-shared" /> 
                        <Add option="-Wl,--entry,DriverEntry" /> 
                        <Add option="-Wl,--file-alignment,0x1000" /> 
                        <Add option="-Wl,--section-alignment,0x1000" /> 
                        <Add option="-Wl,--image-base,0x00010000" /> 
                        <Add library="ntoskrnl" /> 
                        <Add directory="C:/Program Files/TDM-GCC-64/x86_64-w64-mingw32/lib" /> 
                </Linker> 
                <Unit filename="WinMSR.reg" /> 
                <Unit filename="driver.c"> 
                        <Option compilerVar="CC" /> 
                </Unit> 
                <Extensions> 
                        <code_completion /> 
                        <envvars /> 
                        <debugger /> 
                </Extensions> 
        </Project> 
</CodeBlocks_project_file> 
```
# Installation #
Copy the device driver into the Windows drivers directory
```
copy WinMSR.sys C:\Windows\System32\drivers\
```
## Registry ##
Load the WinMSR.reg file into the registry
### WinMSR.reg ###
```ini

REGEDIT4

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinMSR]
"Start"=dword:3
"Type"=dword:1
"ErrorControl"=dword:1
"DisplayName"="WinMSR Driver"
"ImagePath"=hex(2):5c,00,3f,00,3f,00,5c,00,43,00,3a,00,5c,00,57,00,69,00,6e,00,\
64,00,6f,00,77,00,73,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,\
00,5c,00,44,00,72,00,69,00,76,00,65,00,72,00,73,00,5c,00,57,00,69,00,6e,00,\
4d,00,53,00,52,00,2e,00,73,00,79,00,73,00,00,00
```
## Debug ##
Load the "Debug Print Filter.reg" file into the registry to enable `DbgPrint()`
### Debug Print Filter.reg ###
```ini

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter]
"DEFAULT"=dword:00000008
```
# Reboot #
## F8 Key ##
When booting Windows press the F8 key then choose the option to **disable** the driver signature verification
## Execute WinMSR ##
  1. Start DebugView (choose the option `[Capture Kernel]`)
  1. Run a command prompt
    * Start the service
```
net start WinMSR
```
    * Stop the service
```
net stop WinMSR
```
http://cyring.free.fr/images/WinMSR-CoreTemp.JPG
# Author #
_`CyrIng`_
> 
---

