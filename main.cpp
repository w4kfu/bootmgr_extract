#include <Windows.h>
#include <memory.h>
#include <stdio.h>

# define STATUS_SUCCESS 0
# define BMCISig		0x49434D42		// 'BMCI'
# define BMXHSig		0x48584D42		// 'BMXH'

# define MAX(a, b) (((a) > (b)) ? (a) : (b))

typedef struct MFile
{
	HANDLE hFile;
	HANDLE hMap;
	PBYTE pMap;
	DWORD dwSize;
} MFile;

typedef struct BMHeader
{
	DWORD dwSig;
	DWORD dwZSize;
	DWORD dwSize;
	DWORD dwOffset;
} BMHeader;

#pragma pack(push, 1)

typedef struct PARTITION_RECORD
{
    BYTE bBootIndicator;
    BYTE bStartHead;
    BYTE bStartSector;
    BYTE bStartTrack;
    BYTE bOSIndicator;
    BYTE bEndHead;
    BYTE bEndSector;
    BYTE bEndTrack;
    DWORD dwSectorsPreceding;
    DWORD dwSectors;
} PARTITION_RECORD;

typedef struct MBR
{
    BYTE bBootCode[440];
    DWORD dwDiskSignature;
    WORD wUnknow;
    struct PARTITION_RECORD PartitionRecord[4];
    WORD wSignature;
} MBR;

#pragma pack(pop)

NTSTATUS (__stdcall *RtlDecompressBuffer)(
  _In_   USHORT CompressionFormat,
  _Out_  PUCHAR UncompressedBuffer,
  _In_   ULONG UncompressedBufferSize,
  _In_   PUCHAR CompressedBuffer,
  _In_   ULONG CompressedBufferSize,
  _Out_  PULONG FinalUncompressedSize
    );

NTSTATUS (__stdcall *RtlGetCompressionWorkSpaceSize)(
  _In_   USHORT CompressionFormatAndEngine,
  _Out_  PULONG CompressBufferWorkSpaceSize,
  _Out_  PULONG CompressFragmentWorkSpaceSize
);

int FindPartition(VOID)
{
	HANDLE hFile;
	int NumPart = -1;
	MBR mbr;
	DWORD dwRead;
    DWORD i;

	hFile = CreateFileA("\\\\.\\PhysicalDrive0", 
							GENERIC_READ,
							FILE_SHARE_READ,
							NULL, 
							OPEN_EXISTING, 
							0, 
							NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "[-] CreateFileA() failed", "ERROR", 0);
		return NumPart;
	}
	ReadFile(hFile, &mbr, sizeof (struct MBR), &dwRead, NULL);
	if (dwRead != sizeof (struct MBR))
	{
		MessageBoxA(NULL, "[-] ReadFile() failed", "ERROR", 0);
		return NumPart;
	}
    for (i = 0; i < 4; i++)
    {
        if ((mbr.PartitionRecord[i].bBootIndicator & 0x80) &&
			mbr.PartitionRecord[i].bOSIndicator == 0x07)
        {
            return (i + 1);
        }
    }
	return NumPart;
}

BMHeader *FindBMData(PBYTE pIn, PBYTE pInEnd)
{
	BMHeader *bm_Head = NULL;

	while (((pIn = (PBYTE)memchr(pIn, 'B', pInEnd - pIn - 3)) != NULL) && 
			(*(DWORD*)pIn != BMCISig) && (*(DWORD*)pIn != BMXHSig))
	{
		++pIn;
	}
	if (pIn == NULL)
		return NULL;
	bm_Head = (BMHeader*)pIn;
	if ((pIn + bm_Head->dwOffset + bm_Head->dwZSize) > pInEnd)
		return NULL;
	return bm_Head;
}

BOOL MapFileRead(LPCSTR lpFileName, struct MFile *mFile)
{
	mFile->hFile = CreateFileA(lpFileName, 
							GENERIC_READ,
							FILE_SHARE_READ,
							NULL, 
							OPEN_EXISTING, 
							0, 
							NULL);
	if (mFile->hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "[-] CreateFileA() failed", "ERROR", 0);
		return FALSE;
	}
	mFile->dwSize = GetFileSize(mFile->hFile, NULL);
	mFile->hMap = CreateFileMapping(mFile->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (mFile->hMap == 0)
	{
		MessageBoxA(NULL, "[-] CreateFileMapping() failed", "ERROR", 0);
		CloseHandle(mFile->hFile);
		return FALSE;
	}
	mFile->pMap = (PBYTE)MapViewOfFile(mFile->hMap, FILE_MAP_READ, 0, 0, 0);
	if (mFile->pMap== 0)
	{
		MessageBoxA(NULL, "[-] MapViewOfFile() failed", "ERROR", 0);
		CloseHandle(mFile->hFile);
		CloseHandle(mFile->hMap);
		return FALSE;
	}
	return TRUE;
}

BOOL WriteToFile(PBYTE pBuffer, DWORD dwSize)
{
	OPENFILENAMEA tmpOfn;
	HANDLE hFile = NULL;
	char fileBuff[MAX_PATH];
	DWORD dwWritten;

	ZeroMemory(&tmpOfn, sizeof(tmpOfn));
	tmpOfn.lStructSize = sizeof(tmpOfn);
	tmpOfn.hwndOwner = NULL;
	tmpOfn.lpstrFile = fileBuff;
	tmpOfn.lpstrFile[0] = '\0';
	tmpOfn.nMaxFile = sizeof(fileBuff);
	tmpOfn.lpstrFilter = "executable Files (*.Exe)\0*.exe\0\0";
	tmpOfn.nFilterIndex = 1;
	tmpOfn.lpstrFileTitle = NULL;
	tmpOfn.nMaxFileTitle = 0;
	tmpOfn.lpstrInitialDir = NULL;
	tmpOfn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetSaveFileNameA(&tmpOfn) == TRUE)
	{
		hFile = CreateFileA(tmpOfn.lpstrFile,
		GENERIC_WRITE,
		0,
		(LPSECURITY_ATTRIBUTES) NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		(HANDLE) NULL);
	}
	else
	{
		return FALSE;
	}
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "[-] CreateFileA() failed", "ERROR", 0);
	}
	WriteFile(hFile, pBuffer, dwSize, &dwWritten, NULL);
	if (dwWritten != dwSize)
	{
		MessageBoxA(NULL, "[-] WriteFile() failed", "ERROR", 0);
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);
	return TRUE;
}

VOID CleanMFile(struct MFile *mFile)
{
	CloseHandle(mFile->hFile);
	CloseHandle(mFile->hMap);
	UnmapViewOfFile(mFile->pMap);
}

int CALLBACK WinMain(
  _In_  HINSTANCE hInstance,
  _In_  HINSTANCE hPrevInstance,
  _In_  LPSTR lpCmdLine,
  _In_  int nCmdShow
)
{
	MFile mBootmgr;
	BMHeader *bm_Head = NULL;
	PBYTE pBuffer = NULL;
	ULONG FinalUnComp;
	int NumPart = 0;
	char PathBootmgr[MAX_PATH];
	USHORT CompressionFormat;
	ULONG CompressBufferWorkSpaceSize = 0, CompressFragmentWorkSpaceSize = 0;
	ULONG SizeBuff;

	if ((NumPart = FindPartition()) == -1)
	{
		return 1;
	}
	sprintf_s(PathBootmgr, MAX_PATH - 1, "\\\\.\\HarddiskVolume%d\\bootmgr", NumPart);
	if (MapFileRead(PathBootmgr, &mBootmgr) == FALSE)
	{
		return 1;
	}
	bm_Head = FindBMData(mBootmgr.pMap, mBootmgr.pMap + mBootmgr.dwSize);
	if (bm_Head == NULL)
	{
		MessageBoxA(NULL, "[-] FindBMData() failed", "ERROR", 0);
		goto end;
	}
	RtlDecompressBuffer = (long (__stdcall *)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "RtlDecompressBuffer");
	if (RtlDecompressBuffer == NULL)
	{
		MessageBoxA(NULL, "[-] GetProcAddress() failed", "ERROR", 0);
		goto end;
	}
	if (bm_Head->dwSig == BMCISig)
	{
		CompressionFormat = COMPRESSION_FORMAT_LZNT1;
	}
	else
		CompressionFormat = 0x104; // COMPRESSION_XPRESS_HUFF
	RtlGetCompressionWorkSpaceSize = (long (__stdcall *)(USHORT, PULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetCompressionWorkSpaceSize");
	if (RtlGetCompressionWorkSpaceSize == NULL)
	{
		MessageBoxA(NULL, "[-] GetProcAddress() failed", "ERROR", 0);
		goto end;
	}
	if (RtlGetCompressionWorkSpaceSize(CompressionFormat, &CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize) != STATUS_SUCCESS)
	{
		MessageBoxA(NULL, "[-] RtlGetCompressionWorkSpaceSize() failed", "ERROR", 0);
		goto end;
	}

	SizeBuff = MAX(bm_Head->dwSize, MAX(CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize));

	pBuffer = (PBYTE)VirtualAlloc(NULL, SizeBuff, MEM_COMMIT, PAGE_READWRITE);
	if (pBuffer == NULL)
	{
		MessageBoxA(NULL, "[-] VirtualAlloc() failed", "ERROR", 0);
		goto end;
	}

	if (RtlDecompressBuffer(CompressionFormat, 
		pBuffer, 
		SizeBuff, 
		(PBYTE)bm_Head + bm_Head->dwOffset, 
		bm_Head->dwZSize, 
		&FinalUnComp) != STATUS_SUCCESS)
	{
		MessageBoxA(NULL, "[-] RtlDecompressBuffer() failed", "ERROR", 0);
	}
	else
	{
		WriteToFile(pBuffer, SizeBuff);
	}
	VirtualFree(pBuffer, SizeBuff, 0);
end:
	CleanMFile(&mBootmgr);
	return 0;
}