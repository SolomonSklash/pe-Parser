#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <string>
#include <iostream>

void fileInformation(char& filenamePath, DWORD nNumberOfBytesToRead, HANDLE loadFile)
{
	printf("\n----------------- File Information -----------------\n\n");
	printf("File name: \t %s\n", &filenamePath);
	printf("File size: \t %d Kb\n", nNumberOfBytesToRead);

	// WIN32_FILE_ATTRIBUTE_DATA  + GetFileAttributesEx to pull basic file information

	WIN32_FILE_ATTRIBUTE_DATA fileInfo = { 0 };
	if (GetFileAttributesExA((LPCSTR)&filenamePath, GetFileExInfoStandard, &fileInfo) != 0)
	{
		SYSTEMTIME systemTime = { 0 };
		FileTimeToSystemTime(&fileInfo.ftCreationTime, &systemTime);

		fprintf(stdout,
			"Creation Date: \t %04d-%02d-%02d %02d:%02d:%02d\n",
			systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond
			);
	}

	exit(1);
}

void headerInformation(LPVOID lpBuffer, char& filenamePath, DWORD nNumberOfBytesToRead)
{
	PIMAGE_DOS_HEADER dosHeader = { 0 };
	PIMAGE_NT_HEADERS ntHeader = { 0 };
	
	dosHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	printf("\n----------------- Dos Header -----------------\n\n");
	printf("Value\t\tMember\t	Description\n\n");
	printf("0x%x \t	e_magic\t	Magic Bytes\n", dosHeader->e_magic);
	printf("0x%x \t	e_cblp\t	Bytes on last page of file\n", dosHeader->e_cblp);
	printf("0x%x \t	e_cp\t	Pages in file\n", dosHeader->e_cp);
	printf("0x%x \t	e_crlc\t	Relocations\n", dosHeader->e_crlc);
	printf("0x%x \t	e_cparhdr\tSize of header in paragraphsn\n", dosHeader->e_cparhdr);
	printf("0x%x \t	e_minalloc\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("0x%x \t	e_maxalloc\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("0x%x \t	e_ss\t	Initial (relative) SS value\n", dosHeader->e_ss);
	printf("0x%x \t	e_sp\t	Initial SP value\n", dosHeader->e_sp);
	printf("0x%x \t	e_csum\t	Checksum\n", dosHeader->e_csum);
	printf("0x%x \t	e_ip\t	Initial IP value\n", dosHeader->e_ip);
	printf("0x%x \t	e_cs\t	Initial (relative) CS value\n", dosHeader->e_cs);
	printf("0x%x \t	e_lfarlc\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("0x%x \t	e_ovno\t	Overlay number\n", dosHeader->e_ovno);
	printf("0x%x \te_lfanew\tFile address of new exe header\n", dosHeader->e_res);

	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + dosHeader->e_lfanew);

	printf("\n----------------- NT Headers -----------------\n\n");
	printf("Value\t\tMember\t	Description\n\n");
	const char* sigValue = { 0 };
	if (ntHeader->Signature = IMAGE_DOS_SIGNATURE)
	{
		sigValue = "IMAGE_DOS_SIGNATURE";
	}
	printf("0x%x \t\tSignature \te_res2 - %s \n", ntHeader->Signature, sigValue);
	

	printf("\n----------------- File Header -----------------\n\n");

	DWORD Machine = ntHeader->FileHeader.Machine;
	switch (Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		printf("0x%x \t\tMachine\t\tImage file architecture is x86\n", Machine);
		break;
	case IMAGE_FILE_MACHINE_IA64:
		printf("0x%x \t\tMachine\t\tImage file architecture is Intel Itanium\n", Machine);
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		printf("0x%x \t\tMachine\t\tImage file architecture is x64 Itanium\n", Machine);
		break;
	}

	printf("0x%x \t\tNumberOfSection  \n", ntHeader->FileHeader.NumberOfSections);
	printf("0x%x \tTimeDateStamp  \t Compilation Timestamp\n", ntHeader->FileHeader.TimeDateStamp); 
	printf("0x%x \t\tPointerToSymbolTable  \n", ntHeader->FileHeader.PointerToSymbolTable);
	printf("0x%x \t\tNumberOfSymbols  \n", ntHeader->FileHeader.NumberOfSymbols);
	printf("0x%x \t\tSizeOfOptionalHeader  \n", ntHeader->FileHeader.SizeOfOptionalHeader);

	const char* characteristics = { 0 };

	switch (ntHeader->FileHeader.Characteristics)
	{
	case IMAGE_FILE_EXECUTABLE_IMAGE:
		characteristics = "IMAGE_FILE_EXECUTABLE_IMAGE";
	}

	printf("0x%x \t\tCharacteristics  \n\t %s \n", ntHeader->FileHeader.Characteristics, characteristics);

	printf("\n----------------- Optional Header -----------------\n\n");

	WORD magic = ntHeader->OptionalHeader.Magic;

	const char* magic_value = { 0 };
	switch (magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		printf("0x%x\t\tThe file is a 32BIT executable image\n", magic);
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		printf("0x%x\t\tThe file is a 64BIT executable image\n", magic);
		break;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		printf("0x%x\t\tThe file is a ROM image\n", magic);
		break;
	}

	printf("0x%x \t\tMagic  \n", ntHeader->OptionalHeader.Magic);
	printf("0x%x \t\tMajorLinkerVersion  \n", ntHeader->OptionalHeader.MajorLinkerVersion);
	printf("0x%x \t\tMinorLinkerVersion  \n", ntHeader->OptionalHeader.MinorLinkerVersion);
	printf("0x%x \t\tSizeOfCode  \n", ntHeader->OptionalHeader.SizeOfCode);
	printf("0x%x \t\tSizeOfInitializedData  \n", ntHeader->OptionalHeader.SizeOfInitializedData);
	printf("0x%x \t\tSizeOfUninitializedData  \n", ntHeader->OptionalHeader.SizeOfUninitializedData);
	printf("0x%x \t\tAddressOfEntryPoint  \n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	printf("0x%x \t\tBaseOfCode  \n", ntHeader->OptionalHeader.BaseOfCode);
	printf("0x%x \tBaseOfData  \n", ntHeader->OptionalHeader.BaseOfData);
	printf("0x%x \t\tImageBase  \n", ntHeader->OptionalHeader.ImageBase);
	printf("0x%x \t\tSectionAlignment  \n", ntHeader->OptionalHeader.SectionAlignment);
	printf("0x%x \t\tFileAlignment  \n", ntHeader->OptionalHeader.FileAlignment);
	printf("0x%x \t\tMajorOperatingSystemVersion  \n", ntHeader->OptionalHeader.MajorOperatingSystemVersion);
	printf("0x%x \t\tMinorOperatingSystemVersion  \n", ntHeader->OptionalHeader.MinorOperatingSystemVersion);
	printf("0x%x \t\tMajorImageVersion  \n", ntHeader->OptionalHeader.MajorImageVersion);
	printf("0x%x \t\tMinorImageVersion  \n", ntHeader->OptionalHeader.MinorImageVersion);
	printf("0x%x \t\tMajorSubsystemVersion  \n", ntHeader->OptionalHeader.MajorSubsystemVersion);
	printf("0x%x \t\tMinorSubsystemVersion  \n", ntHeader->OptionalHeader.MinorSubsystemVersion);
	printf("0x%x \t\tWin32VersionValue  \n", ntHeader->OptionalHeader.Win32VersionValue);
	printf("0x%x \t\tSizeOfImage  \n", ntHeader->OptionalHeader.SizeOfImage);
	printf("0x%x \t\tSizeOfHeaders  \n", ntHeader->OptionalHeader.SizeOfHeaders);
	printf("0x%x \tCheckSum  \n", ntHeader->OptionalHeader.CheckSum);

	const char* subsystem_value = { 0 };
	switch (ntHeader->OptionalHeader.Subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		subsystem_value = "IMAGE_SUBSYSTEM_UNKNOWN";
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		subsystem_value = "IMAGE_SUBSYSTEM_NATIVE";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem_value = "IMAGE_SUBSYSTEM_WINDOWS_GUI";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem_value = "IMAGE_SUBSYSTEM_WINDOWS_CUI";
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		subsystem_value = "IMAGE_SUBSYSTEM_OS2_CUI";
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem_value = "IMAGE_SUBSYSTEM_POSIX_CUI";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem_value = "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem_value = "IMAGE_SUBSYSTEM_EFI_APPLICATION";
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem_value = "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem_value = "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem_value = "IMAGE_SUBSYSTEM_EFI_ROM";
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		subsystem_value = "IMAGE_SUBSYSTEM_XBOX";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		subsystem_value = "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
		break;
	}

	printf("0x%x \t\tSubsystem  - %s \n", ntHeader->OptionalHeader.Subsystem, subsystem_value);
	printf("0x%x \t\tDllCharacteristics  \n", ntHeader->OptionalHeader.DllCharacteristics);
	printf("0x%x \tSizeOfStackReserve  \n", ntHeader->OptionalHeader.SizeOfStackReserve);
	printf("0x%x \t\tSizeOfStackCommit  \n", ntHeader->OptionalHeader.SizeOfStackCommit);
	printf("0x%x \t\tSizeOfHeapReserve  \n", ntHeader->OptionalHeader.SizeOfHeapReserve);
	printf("0x%x \t\tSizeOfHeapCommit  \n", ntHeader->OptionalHeader.SizeOfHeapCommit);
	printf("0x%x \tLoaderFlags  \n", ntHeader->OptionalHeader.LoaderFlags);
	printf("0x%x \t\tNumberOfRvaAndSizes  \n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);


	//printf("\n----------------- Data Directories -----------------\n\n");


	printf("\n----------------- Section Headers -----------------\n\n");
		
	PIMAGE_SECTION_HEADER imageSectionHeaderStruct = { 0 };
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		imageSectionHeaderStruct = (PIMAGE_SECTION_HEADER)((DWORD)lpBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	}
	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		imageSectionHeaderStruct = (PIMAGE_SECTION_HEADER)((DWORD)lpBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	}

	int numSections = ntHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < numSections; i++)
	{
		printf("SECTION HEADER #%d\n", i);
		printf("\t%s\n", imageSectionHeaderStruct->Name);
		printf("\t\tVirtual Size: 0x%x\n", imageSectionHeaderStruct->Misc.VirtualSize);
		printf("\t\tVirtual Address: 0x%x\n", imageSectionHeaderStruct->VirtualAddress);
		printf("\t\tRaw Size: 0x%x\n", imageSectionHeaderStruct->SizeOfRawData);
		printf("\t\tRaw Address: 0x%x\n", imageSectionHeaderStruct->PointerToRawData);
		printf("\t\tReloc Address: 0x%x\n", imageSectionHeaderStruct->PointerToRelocations);
		printf("\t\tRelocations Number: 0x%x\n", imageSectionHeaderStruct->NumberOfRelocations);
		printf("\t\tLine Numbers: 0x%x\n", imageSectionHeaderStruct->NumberOfLinenumbers);
		printf("\t\tCharacteristics: 0x%x\n", imageSectionHeaderStruct->Characteristics);
		imageSectionHeaderStruct++;
	}

	
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		fprintf(stdout,
			"\n\tpeParser: 	A utility for parsing PE files formats and structures\n"
			"\tExample:	peParser.exe /OVERVIEW <file.exe>\n\n"
			"\tUsage		Description\n"
			"\t-----		-----------------------------------------------------------------\n"
			"\t/OVERVIEW	List file properties and summary information\n"
			"\t/HEADERS	List PE header structure's information\n"
			"\t/IMPORTS	List IAT information, DLL and function imports\n"
			"\t/EXPORTS	List EAT information, export related functions\n"
			"\t/SECTIONS	List section related information\n"
		);
		exit(1);
	}

	char filenamePath[255] = { 0 };
	memcpy_s(&filenamePath, 255, argv[2], 255);

	HANDLE loadFile = CreateFileA(filenamePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (loadFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] Failed to get a handle to the file - Error Code (%d)\n", GetLastError());
		CloseHandle(loadFile);
		exit(1);
	}

	DWORD nNumberOfBytesToRead = GetFileSize(loadFile, NULL);
	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, nNumberOfBytesToRead);

	DWORD lpNumberOfBytesRead = { 0 };
	if (!ReadFile(loadFile, lpBuffer, nNumberOfBytesToRead, &lpNumberOfBytesRead, NULL))
	{
		printf("[!] Failed to read the file - Error Code (%d)\n", GetLastError());
		CloseHandle(loadFile);
		exit(1);
	}

	// we need add imports, exports, and section information + hashes

	if (strcmp(argv[1], "/HEADERS") == 0)
	{
		headerInformation(lpBuffer, *filenamePath, nNumberOfBytesToRead);
	}
	if (strcmp(argv[1], "/OVERVIEW") == 0)
	{
		fileInformation(*filenamePath, nNumberOfBytesToRead, loadFile);
	}

	CloseHandle(loadFile);
}
