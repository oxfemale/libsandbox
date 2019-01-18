
#include <ntstatus.h>

#include "utils_general.h"
#include "utils_fs.h"
#include "hfs.h"

#define PRINT_DIVIDER DEBUG_PRINT("--------------------")

NTSTATUS NTAPI hfs_NtCreateFile(PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtCreateFile]");

    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    if(utils_fs_resolve_path(ObjectAttributes->RootDirectory,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
            if(use_sandbox_path(processed_input_path,sandbox_path,DesiredAccess,CreateOptions,CreateDisposition)){
                UNICODE_STRING sbp;
                PUNICODE_STRING backup_object_attributes;
                HANDLE root_backup = ObjectAttributes->RootDirectory;
                utils_general_DBG_printfW(L"Use Sandbox Path: YES!");
                ObjectAttributes->RootDirectory = NULL;
                ntdll_RtlInitUnicodeString(&sbp,sandbox_path);
                backup_object_attributes = ObjectAttributes->ObjectName;
                ObjectAttributes->ObjectName = &sbp;
                result = ntdll_NtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
                ObjectAttributes->ObjectName = backup_object_attributes;
                ObjectAttributes->RootDirectory = root_backup;
                PRINT_DIVIDER;
                return result;
            }
        }
    }
    result = ntdll_NtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtOpenFile]");
    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    if(utils_fs_resolve_path(ObjectAttributes->RootDirectory,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
            if(use_sandbox_path(processed_input_path,sandbox_path,DesiredAccess,OpenOptions,0)){
                UNICODE_STRING sbp;
                PUNICODE_STRING backup_object_attributes;
                utils_general_DBG_printfW(L"Use Sandbox Path: YES!");
                HANDLE root_backup = ObjectAttributes->RootDirectory;
                ObjectAttributes->RootDirectory = NULL;
                ntdll_RtlInitUnicodeString(&sbp,sandbox_path);
                backup_object_attributes = ObjectAttributes->ObjectName;
                ObjectAttributes->ObjectName = &sbp;
                result = ntdll_NtOpenFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,ShareAccess,OpenOptions);
                ObjectAttributes->ObjectName = backup_object_attributes;
                ObjectAttributes->RootDirectory = root_backup;
                PRINT_DIVIDER;
                return result;
            }
        }
    }

    result = ntdll_NtOpenFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,ShareAccess,OpenOptions);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtQueryAttributesFile]");



    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;

    if(utils_fs_resolve_path(ObjectAttributes->RootDirectory,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
            if(use_sandbox_path(processed_input_path,sandbox_path,GENERIC_READ,0,0)){
                UNICODE_STRING sbp;
                PUNICODE_STRING backup_object_attributes;
                utils_general_DBG_printfW(L"Use Sandbox Path: YES!");
                HANDLE root_backup = ObjectAttributes->RootDirectory;
                ObjectAttributes->RootDirectory = NULL;
                ntdll_RtlInitUnicodeString(&sbp,sandbox_path);
                backup_object_attributes = ObjectAttributes->ObjectName;
                ObjectAttributes->ObjectName = &sbp;
                result = ntdll_NtQueryAttributesFile(ObjectAttributes,FileInformation);
                ObjectAttributes->ObjectName = backup_object_attributes;
                ObjectAttributes->RootDirectory = root_backup;
                PRINT_DIVIDER;
                return result;
            }
        }
    }

    result = ntdll_NtQueryAttributesFile(ObjectAttributes,FileInformation);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtOpenDirectoryObject]");

    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    if(utils_fs_resolve_path(ObjectAttributes->RootDirectory,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
            if(use_sandbox_path(processed_input_path,sandbox_path,DesiredAccess,0,0)){
                UNICODE_STRING sbp;
                PUNICODE_STRING backup_object_attributes;
                utils_general_DBG_printfW(L"Use Sandbox Path: YES!");
                HANDLE root_backup = ObjectAttributes->RootDirectory;
                ObjectAttributes->RootDirectory = NULL;
                ntdll_RtlInitUnicodeString(&sbp,sandbox_path);
                backup_object_attributes = ObjectAttributes->ObjectName;
                ObjectAttributes->ObjectName = &sbp;
                result = ntdll_NtOpenDirectoryObject(DirectoryHandle,DesiredAccess,ObjectAttributes);
                ObjectAttributes->ObjectName = backup_object_attributes;
                ObjectAttributes->RootDirectory = root_backup;
                PRINT_DIVIDER;
                return result;
            }
        }
    }

    result = ntdll_NtOpenDirectoryObject(DirectoryHandle,DesiredAccess,ObjectAttributes);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PVOID Attributes){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtQueryFullAttributesFile]");
    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    if(utils_fs_resolve_path(ObjectAttributes->RootDirectory,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
            if(use_sandbox_path(processed_input_path,sandbox_path,GENERIC_READ,0,0)){
                UNICODE_STRING sbp;
                PUNICODE_STRING backup_object_attributes;
                utils_general_DBG_printfW(L"Use Sandbox Path: YES!");
                HANDLE root_backup = ObjectAttributes->RootDirectory;
                ObjectAttributes->RootDirectory = NULL;
                ntdll_RtlInitUnicodeString(&sbp,sandbox_path);
                backup_object_attributes = ObjectAttributes->ObjectName;
                ObjectAttributes->ObjectName = &sbp;
                result = ntdll_NtQueryFullAttributesFile(ObjectAttributes,Attributes);
                ObjectAttributes->ObjectName = backup_object_attributes;
                ObjectAttributes->RootDirectory = root_backup;
                PRINT_DIVIDER;
                return result;
            }
        }
    }

    result = ntdll_NtQueryFullAttributesFile(ObjectAttributes,Attributes);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtOpenSymbolicLinkObject]");
    NTSTATUS result = STATUS_SUCCESS;
    utils_general_DBG_printfW(L"Input Path: ");
    result = ntdll_NtOpenSymbolicLinkObject(LinkHandle,DesiredAccess,ObjectAttributes);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtQueryDirectoryFile]");
    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    wchar_t* filename_ptr = NULL;
    unsigned int filename_len = 0;
    if(FileName){
        filename_ptr = FileName->Buffer;
        filename_len = FileName->Length;
    }
    if(utils_fs_resolve_path(FileHandle,filename_ptr,filename_len,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);

        }
    }
    result = ntdll_NtQueryDirectoryFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,FileInformation,Length,FileInformationClass,ReturnSingleEntry,FileName,RestartScan);
    PRINT_DIVIDER;
    return result;
}
NTSTATUS NTAPI hfs_NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName){
    PRINT_DIVIDER;
    DEBUG_PRINT("[NtQueryDirectoryFileEx]");
    NTSTATUS result = STATUS_SUCCESS;
    wchar_t* processed_input_path = NULL;
    wchar_t* filename_ptr = NULL;
    unsigned int filename_len = 0;
    if(FileName){
        filename_ptr = FileName->Buffer;
        filename_len = FileName->Length;
    }
    if(utils_fs_resolve_path(FileHandle,filename_ptr,filename_len,&processed_input_path)){
        utils_general_DBG_printfW(L"Input Path: %s",processed_input_path);
        wchar_t* sandbox_path = NULL;
        if(utils_fs_generate_sandbox_path(processed_input_path,&sandbox_path)){
            utils_general_DBG_printfW(L"Sandbox Path: %s",sandbox_path);
        }
    }

    result = ntdll_NtQueryDirectoryFileEx(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,FileInformation,Length,FileInformationClass,QueryFlags,FileName);
    PRINT_DIVIDER;
    return result;
}
