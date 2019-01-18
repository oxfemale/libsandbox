#include <windows.h>
#include <ntstatus.h>

#include "ntdll.h"
#include "utils_general.h"
#include "utils_str.h"
#include "utils_fs.h"
#include "hashmap.h"

#define ENVAR_SANDBOX_ROOT L"SANDBOX_ROOT"
#define ENVAR_APP_ROOT     L"APP_ROOT"

static wchar_t* default_sandbox_root = L"C:\\SANDBOX";
static wchar_t* default_app_root = L"C:\\XSXAPPS\\6c55bcaa92a04c12\\DATA\\0000";

//#define APP_ROOT     L"C:\\XSXAPPS\\6c55bcaa92a04c12\\DATA\\0000"
//#define PROFILE_ROOT L"\\Users\\merca"

#define REPL_APP_ROOT L"\\[APP_ROOT]"
#define REPL_PROFILE_ROOT L"\\Users\\PROFILE"

static wchar_t* g_sandbox_root;
static wchar_t* g_app_root;
static wchar_t* g_profile_root;




#define NT_PREFIX L"\\??\\"
#define UNC_PREFIX L"\\\\?\\"

#define COPY_BUFFER_SZ 16384
#define FILE_OPENED 0x00000001
#define FILE_OVERWRITTEN 0x00000003

struct FS_Entry{
    BOOL         last_use_sandbox_path;
    BOOL         input_path_exists;
    BOOL         last_is_directory;
    BOOL         last_is_read;
    BOOL         last_is_write;
    wchar_t*     sandbox_path;
};

static map_t fs_map;



BOOL copy_file(const wchar_t* source_path, const wchar_t* dest_path){
    NTSTATUS result = 0;
    HANDLE hSrc;
    HANDLE hDest;
    unsigned char copy_buffer[COPY_BUFFER_SZ];

    // Open Source File
    OBJECT_ATTRIBUTES source_oa;
    UNICODE_STRING source_ustr;
    IO_STATUS_BLOCK source_io;
    ntdll_RtlInitUnicodeString(&source_ustr,source_path);
    InitializeObjectAttributes(&source_oa, &source_ustr, OBJ_CASE_INSENSITIVE, 0, 0);

    result = ntdll_NtCreateFile(&hSrc,GENERIC_READ,&source_oa,&source_io,0,0,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN,FILE_NON_DIRECTORY_FILE,NULL,0);
    if(result){
        utils_general_DBG_printfW(L"NtOpenFile: %s Copy Failed: %04X",source_path,result);
        return FALSE;
    }

    OBJECT_ATTRIBUTES dest_oa;
    memset(&dest_oa,0x00,sizeof(dest_oa));
    UNICODE_STRING dest_ustr;
    IO_STATUS_BLOCK dest_io;

    SECURITY_QUALITY_OF_SERVICE qos;
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)(((FILE_ATTRIBUTE_VALID_FLAGS | FILE_ATTRIBUTE_NORMAL ) >> 16) & 0x3);
    qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    qos.EffectiveOnly = 1;

    ntdll_RtlInitUnicodeString(&dest_ustr,dest_path);
    InitializeObjectAttributes(&dest_oa, &dest_ustr, OBJ_CASE_INSENSITIVE, 0, 0);
    dest_oa.RootDirectory = NULL;
    dest_oa.SecurityDescriptor = NULL;
    dest_oa.SecurityQualityOfService = &qos;

    result = ntdll_NtCreateFile(&hDest,FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,&dest_oa,&dest_io,NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
    if(result){
       CloseHandle(hSrc);
       utils_general_DBG_printfW(L"NtCreateFile %s Copy Failed: %04X",dest_path,result);
       return FALSE;
    }
    DWORD bytes_read = 0xFFFFFFFF;
    while(bytes_read){
        if(!ReadFile(hSrc,copy_buffer,COPY_BUFFER_SZ,&bytes_read,NULL)){
            DEBUG_PRINT("Copy Read Failed!");
            CloseHandle(hSrc);
            CloseHandle(hDest);
            return FALSE;
        }
        if(!WriteFile(hDest,copy_buffer,bytes_read,NULL,NULL)){
            DEBUG_PRINT("Copy Write Failed!");
            CloseHandle(hSrc);
            CloseHandle(hDest);
            return FALSE;
        }
        if(bytes_read != COPY_BUFFER_SZ){
            break; // We're at the end!
        }
    }

    CloseHandle(hSrc);
    CloseHandle(hDest);

    return TRUE;
}

// Based on DesiredAccess, determine if read support is being requested.
BOOL is_read_enabled(DWORD DesiredAccess) {
    // File Checks
    //if (DesiredAccess & READ_CONTROL) { return true; }
    if (DesiredAccess & GENERIC_READ) { return TRUE; }
    if (DesiredAccess & FILE_READ_DATA) { return TRUE; }
    if (DesiredAccess & FILE_READ_ATTRIBUTES) { return TRUE; }
    if (DesiredAccess & FILE_READ_EA) { return TRUE; }
    if (DesiredAccess & FILE_APPEND_DATA) { return TRUE; }
    // Directory Checks
    if (DesiredAccess & FILE_LIST_DIRECTORY) { return TRUE; }
    if (DesiredAccess & FILE_EXECUTE) { return TRUE; }
    if (DesiredAccess & FILE_TRAVERSE) { return TRUE; }

    return FALSE;
}

// Based on DesiredAccess and Disposition, determine if write support is being requested.
BOOL is_write_enabled(DWORD DesiredAccess, DWORD CreateDisposition) {
    // File Checks
    if (DesiredAccess & DELETE) { return TRUE; }
    if (DesiredAccess & GENERIC_WRITE) { return TRUE; }
    if (DesiredAccess & FILE_WRITE_DATA) { return TRUE; }
    if (DesiredAccess & FILE_WRITE_ATTRIBUTES) { return TRUE; }
    if (DesiredAccess & FILE_APPEND_DATA) { return TRUE; }
    if (DesiredAccess & FILE_WRITE_EA) { return TRUE; }
    // Directory Checks
    if (DesiredAccess & FILE_ADD_SUBDIRECTORY) { return TRUE; }
    if (DesiredAccess & FILE_ADD_FILE) { return TRUE; }
    if (DesiredAccess & FILE_DELETE_CHILD) { return TRUE; }
    // If any CreateDisposition flags are set, we're in write mode.
    if (CreateDisposition & FILE_CREATE) { return TRUE; }


    return FALSE;
}

BOOL utils_fs_generate_sandbox_path(const wchar_t* input_path, wchar_t** sandbox_path){
    // Guard for lack of pptr
    if(!sandbox_path){return FALSE;}

    // HACK - if the input path points to our approot replacement, just return.
    // TODO: FIX
    if(wcsstr(input_path,L"[APP_ROOT]")){return FALSE;}

    // Shortcut if we have a mapped entry already.
    struct FS_Entry* centry;
    if(hashmap_get(fs_map,(wchar_t*)input_path, (void**)&centry) == MAP_OK) {
        *sandbox_path = centry->sandbox_path;
        return TRUE;
    }


    wchar_t* working_path = malloc(W_UNC_MAX_PATH_BYTES);
    // Copy Input path to working path.
    wcscpy(working_path,input_path);
    // Trim NT Path
    working_path = repl_wcs(working_path,NT_PREFIX,L"");

    // Scrub Profile Path
    working_path = repl_wcs(working_path,g_profile_root,REPL_PROFILE_ROOT);
    // Scrub APP ROOT Path
    working_path = repl_wcs(working_path,g_app_root,REPL_APP_ROOT);

    // Replace Drive Letter with separator.
    working_path = repl_wcs(working_path,L":",L"");

    // Replace original NT Path with Sandbox Root
    size_t sandbox_path_size = sizeof(NT_PREFIX) + (wstr_size_in_bytes(g_sandbox_root) - 2) + (wstr_size_in_bytes(working_path));
    *sandbox_path = calloc(1,sandbox_path_size);
    wcscat(*sandbox_path,NT_PREFIX);
    wcscat(*sandbox_path,g_sandbox_root);
    // If the working leaf doesn't start with a separator.
    if(working_path[0] != 0x5C){
        wcscat(*sandbox_path,L"\\");
    }
    wcscat(*sandbox_path,working_path);
 //   *sandbox_path = repl_wcs(working_path,NT_PREFIX,g_sandbox_root);

    return TRUE;
}

// Given a path, create a directory.
BOOL create_directory(const wchar_t* inpath) {
    utils_general_DBG_printfW(L"Create Directory: %s",inpath);
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE fh = INVALID_HANDLE_VALUE;
    UNICODE_STRING ntf;
    ntdll_RtlDosPathNameToNtPathName_U(inpath, &ntf, NULL, NULL);
    InitializeObjectAttributes(&oa, &ntf, OBJ_CASE_INSENSITIVE, 0, 0);
    if (ntdll_NtCreateFile(&fh, FILE_READ_DATA | FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)) {
        return FALSE;
    }
    CloseHandle(fh);
    return TRUE;
}

BOOL create_directory_tree(const wchar_t* input_path){
    wchar_t dir_path[UNC_MAX_PATH];
    unsigned int path_size = 0;
    BOOL is_directory= FALSE;
    BOOL dir_exists = FALSE;
    //bool result = utils_fs::path_exists(directory, &fileAttributes);
    // Skip to :
    // Skip to First \\
    // Call path exists with is_dir
    // if(path_exists) and is_dir, keep skipping until false
    // if path exists and is_dir == FALSE, we have to bail out because we can't complete this
    // Until no more \\ are found, we keep going and if we find a !path_exists we create it with a temporary string
    unsigned int input_max = wstr_size_in_bytes(input_path);
    const wchar_t* path_end = wcsstr(input_path,L":") + sizeof(L":");
    while(path_end){
        is_directory = FALSE;
        dir_exists = FALSE;
        path_size = path_end - input_path;
        memset(dir_path,0x00,sizeof(dir_path));
        memcpy(dir_path,input_path,path_size);
        dir_exists = path_exists(dir_path,&is_directory);
        if(!dir_exists) { create_directory(dir_path); }
        else {
            if(!is_directory) {
                DEBUG_PRINT("ERROR - Cannot create directory because the path points to a file.");
                return FALSE;
            }
        }
        // Set it up for the next round
        path_end = wcsstr(path_end+1,L"\\");
        if(!path_end){break;}
        path_end +=  sizeof(L"\\");
        }


    return TRUE;
}

BOOL CreateDirectoryAnyDepth(const wchar_t *path)
{
    wchar_t opath[MAX_PATH];
    wchar_t *p;
    size_t len;
    wcsncpy_s(opath, MAX_PATH,path, sizeof(opath));
    len = wcslen(opath);
    if(opath[len - 1] == L'/')
        opath[len - 1] = L'\0';

    for(p = opath; *p; p++)
    {
        if(*p == L'/' || *p == L'\\')
        {
            *p = L'\0';
            if(!path_exists(opath,NULL))
                create_directory(opath);
            *p = L'\\';
        }
    }
    if(!path_exists(opath,NULL))
        create_directory(opath);

    return TRUE;
}

BOOL path_wildcard_exists(const wchar_t* input_path){
    DEBUG_PRINT("CHECKING PATH WILDCARD EXISTS");
    //return FALSE;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING ntf;
    HANDLE hSrc;
    IO_STATUS_BLOCK io;

    IO_STATUS_BLOCK source_io;
    ntdll_RtlInitUnicodeString(&ntf,input_path);
    InitializeObjectAttributes(&oa, &ntf, OBJ_CASE_INSENSITIVE, 0, 0);
    NTSTATUS result = ntdll_NtOpenFile( &hSrc, GENERIC_READ | SYNCHRONIZE, &oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT );

    if(result){ return FALSE; }
    CloseHandle(hSrc);
    return TRUE;

}

BOOL path_exists(const wchar_t* input_path,BOOL *is_directory){
    OBJECT_ATTRIBUTES oa;
    FILE_BASIC_INFORMATION fbi;
    UNICODE_STRING ntf;
    // HACK : FIX THIS TODO TODO REMEMBER TO FIX THIS SHITHEAD
    if (wcsstr(input_path, L"*")) { return path_wildcard_exists(input_path); }
    ntdll_RtlInitUnicodeString(&ntf,input_path);
    InitializeObjectAttributes(&oa, &ntf, OBJ_CASE_INSENSITIVE, 0, 0);
    fbi.FileAttributes = 0;
    if(!ntdll_NtQueryAttributesFile(&oa, &fbi)){
        if(is_directory){
            if((fbi.FileAttributes & FILE_DIRECTORY_FILE)){
                *is_directory = TRUE;
            }else{
                *is_directory = FALSE;
            }

        }
        return TRUE;
    }
    return FALSE;
}


BOOL parent_path_exists(const wchar_t* input_path, BOOL* is_directory){
    wchar_t parent_path[UNC_MAX_PATH];
    _wsplitpath(input_path,NULL,parent_path,NULL,NULL);
    return path_exists(parent_path,is_directory);

}


// Based upon a file handle, retrieve the full path if possible.
// Parameters:
// void* root_handle - Input handle to the root path whose path we want to resolve.
// const wchar_t* stem_name - An absolute path or optional stem value for the path.
// wchar_t** output_path - Allocated output path
BOOL utils_fs_resolve_path(void* root_handle, const wchar_t* stem_name,unsigned int stem_length_bytes, wchar_t** output_path) {

    // Initial Guard
    // If we don't have an output pointer, we can't do anything.
    if(!output_path){
        DEBUG_PRINT("!output_path");
        return FALSE;
    }


    if(!root_handle && !stem_length_bytes){
        DEBUG_PRINT("No Root Handle and No Path");
        return FALSE;
    }

    void* tmp_path = calloc(1,UNC_MAX_PATH*2);


    if(root_handle){     // Logic for Relative Path
        if (!GetFinalPathNameByHandleW(root_handle, tmp_path, UNC_MAX_PATH, VOLUME_NAME_DOS)) {
            DEBUG_PRINT("[util] ERROR: Could not get path by handle.");
            free(tmp_path);
            return FALSE;
        }
        wcscat(tmp_path, L"\\");
    }else{
        // If there is no root handle and the path doesn't appear to be an absolute filesystem path.
        if(!wcsstr(stem_name,L":")){
            free(tmp_path);
            return FALSE;
        }
    }

    // If we were given a filename as well - append it.
    // Note: There is an edge case where a UNICODE_STRING is initialized with a larger string buffer (partial inits)
    // We have to be sure that the Length parameter is given as size in bytes to ensure we are reading the right path.
    // TODO: UNDO THIS!!!
    if (stem_name) {
        wcscat(tmp_path, stem_name);
        //unsigned int cur_tmp_len = wcslen(tmp_path)*2;
        //memcpy(tmp_path + cur_tmp_len,(unsigned char*)stem_name,stem_length_bytes);

    }



    // Housekeeping.
    *output_path = (wchar_t*)calloc(1,wstr_size_in_bytes(tmp_path));
    if(!*output_path){
        DEBUG_PRINT("!*output_path");
        free(tmp_path);
        return FALSE;
    }
    memcpy(*output_path,(unsigned char*)tmp_path,wstr_size_in_bytes(tmp_path));
    free(tmp_path);
    // Convert UNC Prefix to NT Prefix - this is probably pretty rare.
    *output_path = repl_wcs(*output_path,UNC_PREFIX,NT_PREFIX);
    return TRUE;
}


BOOL use_sandbox_path(const wchar_t* input_path, const wchar_t* sandbox_path, DWORD DesiredAccess,DWORD FileOptions, DWORD FileDisposition){
    struct FS_Entry* centry = NULL;
    // Only use if new entry is needed.
    //



    if(hashmap_get(fs_map,(wchar_t*)input_path,(void**)&centry) == MAP_OK) {

        // Short Circuit.
        if(centry->last_use_sandbox_path){ return TRUE; }
        // Do Some recalculation on an already existing object
        // It might have been read first, now it's write?

    }else{ // This is a new entry - we can jam the pointer
        centry = calloc(1,sizeof(struct FS_Entry));
        if(hashmap_put(fs_map,(wchar_t*) input_path,centry) != MAP_OK){
            DEBUG_PRINT("Hashmap Put Failure!");
            return FALSE;
        }
        centry->sandbox_path = (wchar_t*)sandbox_path;
    }


    // TODO: Check for input_path_key in hashmap
    // TODO: If not found, add it with  the default object and make all changes below to that object.
    // TODO: If found, skip everything below and load stuff from the struct that's possible and short-circuit.



    if(FileOptions & FILE_DIRECTORY_FILE){
        centry->last_is_directory = TRUE;
    }

    BOOL read_requested = is_read_enabled(DesiredAccess);
    BOOL write_requested = is_write_enabled(DesiredAccess,FileDisposition);
    utils_general_DBG_printfA("[READ: %d] [WRITE: %d] [DIR: %d]",read_requested,write_requested,centry->last_is_directory);
    // If flags have changed, we need to re-evaluate paths and any additional steps required.
    if(centry->last_is_read != read_requested || centry->last_is_write != write_requested){
        centry->last_is_write = write_requested;
        centry->last_is_read = read_requested;

        // HACK - REMOVE THIS
        /*
        if(wcsstr(centry->sandbox_path,L"*")){
            centry->last_use_sandbox_path = TRUE;
            return TRUE;
        }
         */

        // Read Only
        // If the sandbox path exists, use it - otherwise, use the input path.
        if(read_requested && ! write_requested){
            if(path_exists(sandbox_path,NULL)){
                centry->last_use_sandbox_path = TRUE;
                return TRUE;
            }
            centry->last_use_sandbox_path = FALSE;
            return FALSE;
        }

        // Write
        // If the parent path doesn't exist, create it - always use sandbox path.
        //
        if(write_requested){
            void* parent_path = calloc(1,UNC_MAX_PATH*2);
            _wsplitpath(sandbox_path,NULL,parent_path,NULL,NULL);
            if(!path_exists(parent_path,NULL)){
                if(!CreateDirectoryAnyDepth(parent_path)){
                    centry->last_use_sandbox_path = FALSE;
                    free(parent_path);
                    return FALSE;
                }
            }
            free(parent_path);
        }    // Secondary Pass - if the input path already exists, we can determine what it is more easily.
        // TODO: Evaluate if we necessarily have to do this every time...
        centry->input_path_exists = path_exists(input_path,&centry->last_is_directory);
        // We're in READ_WRITE mode, CopyOnWrite - always use sandbox path.
        if(read_requested && centry->input_path_exists && !path_exists(sandbox_path,NULL)){
            // Copy on Write
            utils_general_DBG_printfW(L"CopyOnWrite: %s->%s",input_path,sandbox_path);
            if(!copy_file(input_path,sandbox_path)){
                DEBUG_PRINT("COPY ON WRITE FAIL!!!");
                centry->last_use_sandbox_path = FALSE;
                return FALSE;
            }
        }
        centry->last_use_sandbox_path = TRUE;
        return TRUE;
    }

return centry->last_use_sandbox_path;
}

BOOL init_fsutils(){
    DEBUG_PRINT("INIT FSUTILS");
    fs_map = hashmap_new();
    DEBUG_PRINT("GET SANDBOX ROOT");
    if(!utils_general_GetEnvar(ENVAR_SANDBOX_ROOT,&g_sandbox_root)){
        g_sandbox_root = default_sandbox_root;
    }
    DEBUG_PRINT("GET APP ROOT");
    if(!utils_general_GetEnvar(ENVAR_APP_ROOT,&g_app_root)){
        g_app_root = default_app_root;
    }
    DEBUG_PRINT("GET PROFILE ROOT");
    utils_general_get_profile_path(&g_profile_root);

    utils_general_DBG_printfW(L"Sandbox Root: %s",g_sandbox_root);
    utils_general_DBG_printfW(L"App Root: %s",g_app_root);
    utils_general_DBG_printfW(L"Profile Root: %s",g_profile_root);

    return TRUE;
}