//====================================================================
//
// linuxHelpers.cpp
//
// Copyright (C) 2021 Microsoft Corporation
//
// Linux support functions for events.cpp
//
//====================================================================
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <utmp.h>
#include <utmpx.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*double  g_bootSecSinceEpoch = 0;
int     g_clk_tck = 100;
size_t  g_pwEntrySize = 0;
extern uint32_t machineId;
*/

//--------------------------------------------------------------------
//
// GetProcess
//
// Get details of a process from /proc
//
//--------------------------------------------------------------------
/*BOOLEAN GetProcess(
    PSYSMON_EVENT_HEADER Process,
    size_t Len,
    ULONG ProcessId
    )
{
    PSYSMON_PROCESS_CREATE pc = NULL;
    FILE *fp = NULL;
    char pathFile[32];
    ssize_t num_read = 0;
    char imagePath[PATH_MAX];
    char cwd[PATH_MAX];
    char cmdline[128 * 1024];
    size_t dataSize = 0;
    int imagePathLen = 0;
    int cwdLen = 0;
    int cmdlineLen = 0;
    PCHAR ptr = NULL;
    unsigned int uid = 0;
    unsigned int pts = 0;

    if (Process == NULL) {
        return false;
    }

    pc = &Process->m_EventBody.m_ProcessCreateEvent;

    //
    // Get command line, image and working directory
    //
    snprintf( pathFile, 32, "/proc/%d/cmdline", ProcessId );
    fp = fopen( pathFile, "rb" );
    if (fp == NULL) {
        return NULL;
    }
    num_read = fread( cmdline, 1, (128 * 1024) - 1, fp );
    fclose( fp );
    // terminate cmdline
    if (cmdline[num_read - 1] != 0x00) {
        cmdline[num_read] = 0x00;
        num_read++;
    }
    // convert nulls to spaces
    for (int i=0; i<num_read - 1; i++) {
        if (cmdline[i] == 0x00) {
            cmdline[i] = ' ';
        }
    }

    snprintf( pathFile, 32, "/proc/%d/exe", ProcessId );
    num_read = readlink( pathFile, imagePath, PATH_MAX-1 );
    if (imagePath[num_read - 1] != 0x00) {
        imagePath[num_read] = 0x00;
    }
    
    snprintf( pathFile, 32, "/proc/%d/cwd", ProcessId );
    num_read = readlink( pathFile, cwd, PATH_MAX-1 );
    if (cwd[num_read - 1] != 0x00) {
        cwd[num_read] = 0x00;
    }

    snprintf( pathFile, 32, "/proc/%d/loginuid", ProcessId );
    fp = fopen( pathFile, "r" );
    if (fp != NULL) {
        fscanf( fp, "%d", &uid );
        fclose( fp );
    }

    imagePathLen = strlen( imagePath ) + 1;
    cwdLen = strlen( cwd ) + 1;
    cmdlineLen = strlen( cmdline ) + 1;

    // calculate extension sizes and total data size
    dataSize = sizeof( *Process );
    if ( dataSize + imagePathLen > Len ) {
        imagePathLen = 0;
        cwdLen = 0;
        cmdlineLen = 0;
    } else {
        dataSize += imagePathLen;
        if (dataSize + cwdLen > Len ) {
            cwdLen = 0;
            cmdlineLen = 0;
        } else {
            dataSize += cwdLen;
            if ( dataSize + cmdlineLen > Len ) {
                cmdlineLen = Len - dataSize;
            }
            dataSize += cmdlineLen;
        }
    }

    Process->m_EventSize = dataSize;
    Process->m_EventType = ProcessCreate;
    Process->m_FieldFiltered = false;
    Process->m_PreFiltered = false;

    pc->m_ProcessId = ProcessId;
    GetProcessInfo( &pc->m_CreateTime.QuadPart, &pts, &pc->m_ParentProcessId,
            &pc->m_SessionId, &pc->m_ProcessKey, ProcessId );
    pc->m_AuthenticationId.LowPart = uid;
    pc->m_AuthenticationId.HighPart = pts;

    memset( pc->m_Extensions, 0, sizeof(pc->m_Extensions) );
    pc->m_Extensions[PC_ImagePath] = imagePathLen;
    pc->m_Extensions[PC_CommandLine] = cmdlineLen;
    pc->m_Extensions[PC_CurrentDirectory] = cwdLen;

    ptr = (PCHAR)(pc + 1);
    if (imagePathLen > 0) {
        snprintf( ptr, imagePathLen, "%s", imagePath );
        ptr += imagePathLen;
    }
    if (cmdlineLen > 0) {
        snprintf( ptr, cmdlineLen, "%s", cmdline );
        ptr += cmdlineLen;
    }
    if (cwdLen > 0) {
        snprintf( ptr, cwdLen, "%s", cwd );
    }

    return true;
}*/

//--------------------------------------------------------------------
//
// SetBootTime
//
// Sets the boot time and clock tick globals
//
//--------------------------------------------------------------------
/*void SetBootTime()
{
    FILE *fp = NULL;
    double uptimeF = 0.0;
    char machineIdStr[9];
    struct timeval tv;

    fp = fopen( "/proc/uptime", "r" );
    if (fp != NULL) {
        fscanf(fp, "%lf", &uptimeF);
        gettimeofday(&tv, NULL);

        g_bootSecSinceEpoch = (double)tv.tv_sec + ((double)tv.tv_usec / (1000 * 1000)) - uptimeF;
        fclose(fp);
    }

    g_clk_tck = sysconf( _SC_CLK_TCK );
    // if error, set it to the default of 100
    if (g_clk_tck <= 0) {
        g_clk_tck = 100;
    }

    // get passwd entry size, or guess at 4K if not
    g_pwEntrySize = sysconf( _SC_GETPW_R_SIZE_MAX );
    if (g_pwEntrySize == (size_t)-1) {
        g_pwEntrySize = 4096;
    }

    // get the machineId
    fp = fopen( "/etc/machine-id", "r" );
    if (fp != NULL) {
        if (fread( machineIdStr, 1, 8, fp ) == 8) {
            machineIdStr[8] = 0x00;
            machineId = strtol( machineIdStr, NULL, 16 );
        }
        fclose( fp );
    }
}*/

/*
//--------------------------------------------------------------------
//
// GetProcessInfo
//
// Gets the process start time in 100-ns intervals since epoch,
// pts number, process parent ID, session ID and process key
// (end_data address,
// which should a) be randomised for PIE executables and b) be
// depenedent on the size of the text segment in the executable -
// hopefully this makes it difficult to craft a process with a
// pre-determined value.)
//
// ProcessKey is a placeholder until we find a better parameter.
//
//--------------------------------------------------------------------
BOOLEAN GetProcessInfo(
    LONGLONG* StartTime,
    ULONG* Pts,
    ULONG* Ppid,
    ULONG* Sessionid,
    ULONGLONG* ProcessKey,
    ULONG Pid
    )
{
    char statFile[32];
    FILE *fp = NULL;
    char buf[2048];
    size_t num_read = 0;
    char *ptr = NULL;
    double clk_tcks = 0;
    ULONG ppid = 0;
    ULONG pts = 0;
    ULONGLONG end_data;

    if (Pid <= 0) {
        return FALSE;
    }

    snprintf(statFile, 32, "/proc/%d/stat", Pid);
    fp = fopen(statFile, "r");
    if (fp == NULL) {
        return FALSE;
    }

    num_read = fread(buf, 1, 2048, fp);
    buf[num_read] = 0x00;
    fclose(fp);

    //
    // extract known fields from /proc/[pid]/stat
    //
    ptr = strrchr(buf, ')');
    if (ptr == NULL) {
        return FALSE;
    }
    ptr++;
    for (int i=0; i<24; i++) {
        ptr = strchr(ptr+1, ' ');
        if (ptr == NULL) {
            return FALSE;
        }
        if (i==0) {
            sscanf(ptr, "%d", &ppid);
        } else if (i==3) {
            sscanf(ptr, "%d", &pts);
        } else if (i==18) {
            sscanf(ptr, "%lf", &clk_tcks);
        }
    }
    sscanf(ptr, "%ld", &end_data);

    snprintf(statFile, 32, "/proc/%d/sessionid", Pid);
    fp = fopen(statFile, "r");
    if (fp == NULL) {
        return FALSE;
    }
    fscanf(fp, "%d", Sessionid);
    fclose(fp);

    *ProcessKey = end_data;
    *Pts = pts & 0xff;
    *Ppid = ppid;
    *StartTime = (LONGLONG)round(((clk_tcks / g_clk_tck) + g_bootSecSinceEpoch) * 1000 * 1000 * 10);
    return TRUE;
}

//--------------------------------------------------------------------
//
// GetProcessName
//
// Gets the process name into the given string
//
//--------------------------------------------------------------------
BOOLEAN
GetProcessName(
		 	  char* ProcName,
			  int Len,
              int Pid
			  )
{
	char processPath[PATH_MAX];
	char *argv_ptr = NULL;
	FILE *fp = NULL;
	size_t num_read = 0;
    char cmdlineFile[32] = "/proc/self/cmdline";
    char exeFile[32] = "/proc/self/exe";

    if (Len > 1) {
        *ProcName = 0x00;
    } else {
        return FALSE;
    }

    if (Pid > 0) {
        snprintf(cmdlineFile, 32, "/proc/%d/cmdline", Pid);
        snprintf(exeFile, 32, "/proc/%d/exe", Pid);
    }

	fp = fopen(cmdlineFile, "rb");
	if (fp != NULL) {
        num_read = fread(processPath, 1, PATH_MAX-1, fp);
        processPath[num_read] = 0x00;
        fclose(fp);
	}

	if (num_read == 0) {
		num_read = readlink(exeFile, processPath, PATH_MAX-1);
        if ((int64_t)num_read <= 0) {
            return FALSE;
        }
        processPath[num_read] = 0x00;
	}

	argv_ptr = strrchr(processPath, '/');
	if (argv_ptr != NULL) {
		while (*argv_ptr == '/') {
			argv_ptr++;
		}
		if (*argv_ptr == 0x00) {
			return FALSE;
		}
	} else {
		argv_ptr = processPath;
	}
	snprintf(ProcName, Len, "%s", argv_ptr);
	return TRUE;
}

//--------------------------------------------------------------------
//
// StrIsNum
//
// Checks if a string is a number
//
//--------------------------------------------------------------------
BOOLEAN StrIsNum(
    char *s
    )
{
    char *p = s;

    if (p == NULL || *p == 0x00) {
        return false;
    }

    while (*p != 0x00) {
        if (!isdigit(*p)) {
            return false;
        }
        p++;
    }
    return true;
}

//--------------------------------------------------------------------
//
// EnumProcesses
//
// Reimplementation of Windows EnumProcesses. Returns an array of
// process IDs. cb specifies size of array in bytes. lpcbNeeded
// returns number of bytes used.
//
//--------------------------------------------------------------------
BOOLEAN EnumProcesses(
    PDWORD      lpidProcess,
    DWORD       cb,
    PDWORD      lpcbNeeded
    )
{
    DIR *directory;
    struct dirent *entry;
    DWORD count = 0;

    *lpcbNeeded = 0;

    directory = opendir("/proc");
    if (directory == NULL) {
        return false;
    }

    while ((entry = readdir( directory )) != NULL && *lpcbNeeded < cb) {
        if (entry->d_type == DT_DIR && StrIsNum(entry->d_name)) {
            lpidProcess[count++] = atoi(entry->d_name);
            (*lpcbNeeded) += sizeof(DWORD);
        }
    }

    closedir(directory);
    return true;
}

//--------------------------------------------------------------------
//
// StringFromGUID2
//
// Reimplmentation of Windows StringFromGUID2. Makes a string of the
// provided GUID. Returns number of characters (including null).
//
//--------------------------------------------------------------------
int StringFromGUID2(
    const GUID guid,
    PCHAR      lpsz,
    int        cchMax
    )
{
    // target string size includes enclosing braces, hyphens, and null terminator
    int size = (sizeof(guid.Data1) + sizeof(guid.Data2) + sizeof(guid.Data3) +
            sizeof(guid.Data4)) * 2 + 2 + 4 + 1;

    if (cchMax < size) {
        return 0;
    }

    return 1 + snprintf(lpsz, cchMax, "{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
            guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);

}

//--------------------------------------------------------------------
//
// GetLogonTime
//
// Return the logon time, in 100ns intervals since epoch, for given
// user and terminal. LUID->LowPart = uid; LUID->HighPart = #pts
//
//--------------------------------------------------------------------
LARGE_INTEGER GetLogonTime(
    LUID* user_luid
    )
{
    struct passwd pwd;
    struct passwd *entry = NULL;
    char buf[g_pwEntrySize];
    LARGE_INTEGER result = {0,};
    struct utmpx *r;
    struct utmpx s;

    getpwuid_r( user_luid->LowPart, &pwd, buf, g_pwEntrySize, &entry );
    if (entry == NULL) {
        return result;
    }

    snprintf( s.ut_line, UT_LINESIZE, "pts/%d", user_luid->HighPart );

    setutxent();
    while ((r = getutxline(&s)) != (struct utmpx *)NULL) {
        if (strcmp(r->ut_user, pwd.pw_name) == 0) {
            // time since epoch in 100ns intervals
            result.QuadPart = ((uint64_t)r->ut_tv.tv_sec * 1000 * 1000 * 10) + ((uint64_t)r->ut_tv.tv_usec * 10);
            break;
        }
    }

    endutxent();
    return result;
}

//--------------------------------------------------------------------
//
// TranslateSid
//
// Reimplementation of Windows TranslateSid. Converts given UID,
// provided as a SID, to the associated username.
//
//--------------------------------------------------------------------
void TranslateSid(
    PSID   pUserSid,
    PTCHAR Buffer,
    SIZE_T Size
    )
{
    struct passwd pwd;
    struct passwd *entry = NULL;
    char buf[g_pwEntrySize];

    getpwuid_r( (uid_t)*pUserSid, &pwd, buf, g_pwEntrySize, &entry );
    if (entry == NULL) {
        *Buffer = 0x00;
        return;
    }

    snprintf(Buffer, Size, "%s", pwd.pw_name);
}

//--------------------------------------------------------------------
//
// EventDataDescCreate
//
// Linux implementation of EventDataDescCreate
//
//--------------------------------------------------------------------
VOID EventDataDescCreate(
       _In_ PEVENT_DATA_DESCRIPTOR EventDataDescriptor,
       _In_ const PVOID            DataPtr,
       _In_ ULONG                  DataSize
       )
{
    if (EventDataDescriptor == NULL || DataPtr == NULL) {
        return;
    }
    EventDataDescriptor->Ptr = (ULONGLONG)strdup((PCHAR)DataPtr);
    EventDataDescriptor->Size = DataSize;
    EventDataDescriptor->Reserved = 1;
}

//--------------------------------------------------------------------
//
// GetSystemTimeAsLargeInteger
//
// Gets the time since epoch in 100ns intervals
//
//--------------------------------------------------------------------
VOID GetSystemTimeAsLargeInteger(
    PLARGE_INTEGER timestamp
    )
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    // time in 100ns intervals since epoch
    timestamp->QuadPart = (tv.tv_sec * 1000 * 1000 * 10) + (tv.tv_usec * 10);
}

//--------------------------------------------------------------------
//
// LargeTimeToSeconds
//
// Converts a time since epoch in 100ns intervals to a time since
// epoch in seconds
//
//--------------------------------------------------------------------
time_t LargeTimeToSeconds(
    PLARGE_INTEGER timestamp
    )
{
    return (time_t)(timestamp->QuadPart / (1000 * 1000 * 10));
}

//--------------------------------------------------------------------
//
// LargeTimeMilliseconds
//
// Returns the number of millisecond component of a LARGE_INTEGER time
//
//--------------------------------------------------------------------
unsigned int LargeTimeMilliseconds(
    PLARGE_INTEGER timestamp
    )
{
    return (unsigned int)((timestamp->QuadPart / (1000 * 10)) % 1000);
}
*/

#ifdef __cplusplus
}
#endif

