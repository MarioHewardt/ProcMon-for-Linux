//====================================================================
//
// linuxHelpers.h
//
// Copyright (C) 2021 Microsoft Corporation
//
// Functions exported by linuxHelpers.cpp
//
//====================================================================

//
// In linuxHelpers.cpp
//
#include "linuxTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

//BOOLEAN GetProcess( PSYSMON_EVENT_HEADER Process, size_t Len, ULONG ProcessId );
void SetBootTime();
/*BOOLEAN GetProcessInfo( LONGLONG* StartTime, ULONG* Pts, ULONG* Ppid, ULONG* Sessionid, ULONGLONG* ProcessKey, ULONG Pid );
BOOLEAN GetProcessName( char* ProcName, int Len, int Pid );
BOOLEAN StrIsNum( char* s );
BOOLEAN EnumProcesses( DWORD *lpidProcess, DWORD cb, PDWORD lpcbNeeded );
int StringFromGUID2( const GUID guid, PCHAR lpsz, int cchMax );
LARGE_INTEGER GetLogonTime( LUID* user_luid );
VOID EventDataDescCreate( _In_ PEVENT_DATA_DESCRIPTOR EventDataDescriptor,
    _In_ const PVOID DataPtr, _In_ ULONG DataSize );
VOID GetSystemTimeAsLargeInteger( PLARGE_INTEGER timestamp );
time_t LargeTimeToSeconds( PLARGE_INTEGER timestamp );
unsigned int LargeTimeMilliseconds( PLARGE_INTEGER timestamp );
*/ 

#ifdef __cplusplus
}
#endif
