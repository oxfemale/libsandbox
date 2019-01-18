#pragma once

#include <winternl.h>
#include <ntdef.h>

typedef struct _RTLP_CURDIR_REF {
    LONG CurrentDirectoryReferenceCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurrentDirectoryReference;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

// NTDLL Templates
typedef NTSTATUS(NTAPI *pNtCreateFile)(PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(NTAPI *pNtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(NTAPI *pNtQueryAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
typedef NTSTATUS(NTAPI *pNtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
typedef NTSTATUS(NTAPI *pNtQueryDirectoryFileEx)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName);
typedef NTSTATUS(NTAPI *pNtQueryFullAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PVOID Attributes);
typedef NTSTATUS(NTAPI *pNtOpenDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI *pNtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ulProcessFlags, ULONG ulThreadFlags, PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters, void* PsCreateInfo, void* PsAttributeList);
typedef NTSTATUS(NTAPI *pNtOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI *pNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI *pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef BOOLEAN(NTAPI *pRtlDosPathNameToNtPathName_U)(PCWSTR DosPathName, PUNICODE_STRING NtPathName, PCWSTR *PartName, PRTL_RELATIVE_NAME_U RelativeName);
typedef VOID(NTAPI *pRtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef VOID(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef VOID(NTAPI *pRtlCopyUnicodeString)(PUNICODE_STRING  DestinationString, PCUNICODE_STRING SourceString);
typedef NTSTATUS(NTAPI *pRtlSetCurrentDirectory_U)(PUNICODE_STRING Path);
typedef NTSTATUS(NTAPI *pRtlGetCurrentDirectory_U)(ULONG MaximumLength, PWSTR Buffer);

extern pNtProtectVirtualMemory        ntdll_NtProtectVirtualMemory;
extern pNtAllocateVirtualMemory       ntdll_NtAllocateVirtualMemory;
extern pNtWriteVirtualMemory          ntdll_NtWriteVirtualMemory;
extern pNtCreateFile                  ntdll_NtCreateFile;
extern pNtOpenFile                    ntdll_NtOpenFile;
extern pNtQueryAttributesFile         ntdll_NtQueryAttributesFile;
extern pNtQueryDirectoryFileEx        ntdll_NtQueryDirectoryFileEx;
extern pNtQueryFullAttributesFile     ntdll_NtQueryFullAttributesFile;
extern pNtOpenDirectoryObject         ntdll_NtOpenDirectoryObject;
extern pNtCreateUserProcess           ntdll_NtCreateUserProcess;
extern pNtOpenSymbolicLinkObject      ntdll_NtOpenSymbolicLinkObject;
extern pNtQueryDirectoryFile          ntdll_NtQueryDirectoryFile;
extern pRtlCopyUnicodeString          ntdll_RtlCopyUnicodeString;
extern pRtlFreeUnicodeString          ntdll_RtlFreeUnicodeString;
extern pRtlInitUnicodeString          ntdll_RtlInitUnicodeString;
extern pNtQueryInformationFile        ntdll_NtQueryInformationFile;
extern pRtlDosPathNameToNtPathName_U  ntdll_RtlDosPathNameToNtPathName_U;
extern pRtlSetCurrentDirectory_U      ntdll_RtlSetCurrentDirectory_U;
extern pRtlGetCurrentDirectory_U      ntdll_RtlGetCurrentDirectory_U;
BOOL init_ntdll();