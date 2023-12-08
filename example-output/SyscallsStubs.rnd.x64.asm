.data
currentHash     dd  0
returnAddress   dq  0
syscallNumber   dd  0
syscallAddress  dq  0

.code
EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx                       ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress        ; Get a random syscall address
    mov qword ptr [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, syscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]                       ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress]           ; Save the original return address
    call qword ptr [syscallAddress]         ; Call the random syscall instruction
    push qword ptr [returnAddress]          ; Restore the original return address
    ret
WhisperMain ENDP

NtAccessCheck PROC
    mov currentHash, 02C9E332Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    mov currentHash, 003A27F57h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    mov currentHash, 02AB5391Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    mov currentHash, 08E649A02h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    mov currentHash, 0F559E2DAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    mov currentHash, 06CF64F62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallbackReturn ENDP

NtReadFile PROC
    mov currentHash, 066B86A12h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFile ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 025BCAE9Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    mov currentHash, 0CCFB8428h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    mov currentHash, 01F027FD0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    mov currentHash, 0F4181198h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    mov currentHash, 020B20926h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    mov currentHash, 06EF06368h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyPort ENDP

NtSetInformationThread PROC
    mov currentHash, 06B5473F7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationThread ENDP

NtSetEvent PROC
    mov currentHash, 07EE44768h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEvent ENDP

NtClose PROC
    mov currentHash, 094944D26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtQueryObject PROC
    mov currentHash, 09CBC67D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryObject ENDP

NtQueryInformationFile PROC
    mov currentHash, 078DE6158h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtOpenKey PROC
    mov currentHash, 08ADEA579h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKey ENDP

NtEnumerateValueKey PROC
    mov currentHash, 01E1A0189h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateValueKey ENDP

NtFindAtom PROC
    mov currentHash, 0D646D7D4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    mov currentHash, 001204DF4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    mov currentHash, 059ED7852h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryKey ENDP

NtQueryValueKey PROC
    mov currentHash, 01930F45Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 00F812137h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    mov currentHash, 0812484ACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    mov currentHash, 07CEE7C39h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    mov currentHash, 05FCE7517h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFileGather ENDP

NtCreateKey PROC
    mov currentHash, 04A0365A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 03B952177h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    mov currentHash, 034B93726h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    mov currentHash, 0BA0387A2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    mov currentHash, 013A881ACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    mov currentHash, 0DAB42FD5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    mov currentHash, 01F930501h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    mov currentHash, 079D2734Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    mov currentHash, 01C0BD6BDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtOpenProcess PROC
    mov currentHash, 0412944B0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtSetInformationFile PROC
    mov currentHash, 023244E22h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    mov currentHash, 0D64FF69Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    mov currentHash, 019BF1321h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 03AD21C5Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    mov currentHash, 0BB95EF49h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    mov currentHash, 0C1E25400h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    mov currentHash, 0C49F3EF3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    mov currentHash, 017AC232Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    mov currentHash, 0029BD4C5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    mov currentHash, 0989ADE24h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    mov currentHash, 0F9751426h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    mov currentHash, 04B3E6A96h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateKey ENDP

NtOpenFile PROC
    mov currentHash, 0D691DC26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenFile ENDP

NtDelayExecution PROC
    mov currentHash, 004961FE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 060BA6202h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    mov currentHash, 09C33BCA1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtOpenSection PROC
    mov currentHash, 0F4EF17F2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtQueryTimer PROC
    mov currentHash, 0EA5AE4D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimer ENDP

NtFsControlFile PROC
    mov currentHash, 0303B2989h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 00595031Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    mov currentHash, 0923594A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    mov currentHash, 00EA6E68Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    mov currentHash, 0E670E6EAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAttributesFile ENDP

NtClearEvent PROC
    mov currentHash, 0A0B3A925h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearEvent ENDP

NtReadVirtualMemory PROC
    mov currentHash, 00D961311h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    mov currentHash, 0D9732600h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 0A1A53085h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    mov currentHash, 005309710h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateToken ENDP

NtContinue PROC
    mov currentHash, 0BF16AA99h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    mov currentHash, 09331CF0Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    mov currentHash, 00830469Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtYieldExecution PROC
    mov currentHash, 0FC4FBAFBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtYieldExecution ENDP

NtAddAtom PROC
    mov currentHash, 024760726h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtom ENDP

NtCreateEvent PROC
    mov currentHash, 01A3C9C2Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    mov currentHash, 0A1274927h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    mov currentHash, 0E30CE39Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtFlushBuffersFile PROC
    mov currentHash, 02FBCF185h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    mov currentHash, 00B5E7B8Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    mov currentHash, 09F95D341h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcessEx ENDP

NtCreateThread PROC
    mov currentHash, 0248F3E30h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThread ENDP

NtIsProcessInJob PROC
    mov currentHash, 0D4ADDE06h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 041AC3D5Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    mov currentHash, 00F4C03EFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySection ENDP

NtResumeThread PROC
    mov currentHash, 0E2806CA1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtTerminateThread PROC
    mov currentHash, 00EAE5467h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateThread ENDP

NtReadRequestData PROC
    mov currentHash, 0A20A7A30h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadRequestData ENDP

NtCreateFile PROC
    mov currentHash, 0ABBA21ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateFile ENDP

NtQueryEvent PROC
    mov currentHash, 01EDBF680h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEvent ENDP

NtWriteRequestData PROC
    mov currentHash, 05C92A8C0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    mov currentHash, 08897EA68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    mov currentHash, 092345460h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 0339D4373h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    mov currentHash, 08AA679AAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationObject ENDP

NtCancelIoFile PROC
    mov currentHash, 05AC36C5Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFile ENDP

NtTraceEvent PROC
    mov currentHash, 0BE08A4AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceEvent ENDP

NtPowerInformation PROC
    mov currentHash, 08F126A00h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPowerInformation ENDP

NtSetValueKey PROC
    mov currentHash, 00F9AE984h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetValueKey ENDP

NtCancelTimer PROC
    mov currentHash, 01BA78EA3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer ENDP

NtSetTimer PROC
    mov currentHash, 043975514h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer ENDP

NtAccessCheckByType PROC
    mov currentHash, 01CDA026Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    mov currentHash, 0A33B2326h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    mov currentHash, 014CA96D6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov currentHash, 068353E06h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    mov currentHash, 052DF4F46h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    mov currentHash, 0AB50F7B5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtomEx ENDP

NtAddBootEntry PROC
    mov currentHash, 009981900h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    mov currentHash, 011980110h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    mov currentHash, 005D1591Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    mov currentHash, 0871C8385h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    mov currentHash, 015AF5106h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertResumeThread ENDP

NtAlertThread PROC
    mov currentHash, 0102F9E05h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    mov currentHash, 040B96E7Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    mov currentHash, 093BB581Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    mov currentHash, 0173561B7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    mov currentHash, 089A2A018h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    mov currentHash, 02DF55339h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    mov currentHash, 0A0B61C93h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    mov currentHash, 0E572FAE1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    mov currentHash, 03395420Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    mov currentHash, 01E8D0700h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    mov currentHash, 0118C5F4Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    mov currentHash, 03EB22B3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    mov currentHash, 004D90C43h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    mov currentHash, 040D2B05Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    mov currentHash, 0AB358F6Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    mov currentHash, 010AEE4E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    mov currentHash, 0D841C6CDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    mov currentHash, 0F65AA863h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    mov currentHash, 030903503h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    mov currentHash, 016820512h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    mov currentHash, 0653163ABh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    mov currentHash, 0AEA2D323h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    mov currentHash, 021B23C3Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    mov currentHash, 0622253A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    mov currentHash, 0148FD1A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    mov currentHash, 0089E2A13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    mov currentHash, 0EDCDB872h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    mov currentHash, 07762820Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    mov currentHash, 022B3012Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    mov currentHash, 04EDB684Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    mov currentHash, 01DB34B8Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    mov currentHash, 08A99FA65h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    mov currentHash, 09CB98A24h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    mov currentHash, 0552A302Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    mov currentHash, 0069CB4A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    mov currentHash, 03B98BA82h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    mov currentHash, 0B8BC74ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    mov currentHash, 0782278BEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    mov currentHash, 038C00C6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitComplete ENDP

NtCommitEnlistment PROC
    mov currentHash, 0F044EDD6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    mov currentHash, 004932405h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    mov currentHash, 092D55F8Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitTransaction ENDP

NtCompactKeys PROC
    mov currentHash, 0FB80EC2Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompactKeys ENDP

NtCompareObjects PROC
    mov currentHash, 09FD369BFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    mov currentHash, 014CA7C2Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    mov currentHash, 04DD06B0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    mov currentHash, 058F3BB9Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompleteConnectPort ENDP

NtCompressKey PROC
    mov currentHash, 025DD2042h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompressKey ENDP

NtConnectPort PROC
    mov currentHash, 0E671FDDEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov currentHash, 06DD6BE97h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    mov currentHash, 0943BA083h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    mov currentHash, 07AD43439h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    mov currentHash, 04CEB143Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    mov currentHash, 09B39BE73h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    mov currentHash, 0DE52E7E4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    mov currentHash, 040934C0Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    mov currentHash, 02491D0EBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    mov currentHash, 03C9B1C15h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    mov currentHash, 00DB1E7AFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobObject ENDP

NtCreateJobSet PROC
    mov currentHash, 0B03EEA91h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    mov currentHash, 018C94276h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    mov currentHash, 030B41928h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    mov currentHash, 0CF91C202h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    mov currentHash, 04E91A0DAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    mov currentHash, 0723577A3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    mov currentHash, 022252282h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    mov currentHash, 00E814C24h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePagingFile ENDP

NtCreatePartition PROC
    mov currentHash, 0BEA7D03Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePartition ENDP

NtCreatePort PROC
    mov currentHash, 0AFBDD24Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    mov currentHash, 06CD612C5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    mov currentHash, 0379C3806h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateProfile PROC
    mov currentHash, 0C89BC821h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfile ENDP

NtCreateProfileEx PROC
    mov currentHash, 002BBC5E5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    mov currentHash, 052CC7019h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    mov currentHash, 04D97553Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    mov currentHash, 09B0AEFE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    mov currentHash, 00E987251h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    mov currentHash, 092BEDC68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtCreateTimer PROC
    mov currentHash, 01F9BEA10h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer ENDP

NtCreateTimer2 PROC
    mov currentHash, 00F84835Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer2 ENDP

NtCreateToken PROC
    mov currentHash, 00F99E602h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateToken ENDP

NtCreateTokenEx PROC
    mov currentHash, 06784BBC0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    mov currentHash, 03ACADB59h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    mov currentHash, 0042E3CA4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    mov currentHash, 0872D9F40h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    mov currentHash, 0BC9A96C4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    mov currentHash, 024F8AEE6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    mov currentHash, 0B7109850h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    mov currentHash, 001561FD0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    mov currentHash, 0E343C0EDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    mov currentHash, 07D074CB4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugContinue ENDP

NtDeleteAtom PROC
    mov currentHash, 035BBD4A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    mov currentHash, 00195F4EBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    mov currentHash, 019966F68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    mov currentHash, 03D3C2A80h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteFile ENDP

NtDeleteKey PROC
    mov currentHash, 0665B11A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    mov currentHash, 012B41E2Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    mov currentHash, 02D0D36ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    mov currentHash, 03A2F1598h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    mov currentHash, 08E877890h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    mov currentHash, 0746AEB51h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    mov currentHash, 02FB8B58Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    mov currentHash, 00C90C0C5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisplayString ENDP

NtDrawText PROC
    mov currentHash, 0F74EC0E5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDrawText ENDP

NtEnableLastKnownGood PROC
    mov currentHash, 0F82EEE87h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    mov currentHash, 0E45CC1C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    mov currentHash, 03C8C4D6Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    mov currentHash, 0B34A85F7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    mov currentHash, 084A867D4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    mov currentHash, 000CB3E67h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtExtendSection ENDP

NtFilterBootOption PROC
    mov currentHash, 09405F6D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterBootOption ENDP

NtFilterToken PROC
    mov currentHash, 003117798h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterToken ENDP

NtFilterTokenEx PROC
    mov currentHash, 07489A8DCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    mov currentHash, 0D6260C84h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    mov currentHash, 0FDCACE96h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    mov currentHash, 00D334E15h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstructionCache ENDP

NtFlushKey PROC
    mov currentHash, 0152778D4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    mov currentHash, 002D882C0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    mov currentHash, 04390356Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    mov currentHash, 003BF6B65h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    mov currentHash, 0F74DD4F2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    mov currentHash, 0F0AD35E0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    mov currentHash, 00792D5D5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    mov currentHash, 0BEFAB868h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    mov currentHash, 04E864A1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    mov currentHash, 018B0420Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    mov currentHash, 0143368D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    mov currentHash, 066EAA155h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    mov currentHash, 0623D946Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    mov currentHash, 086059C8Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    mov currentHash, 041DB4254h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextProcess ENDP

NtGetNextThread PROC
    mov currentHash, 01409DF26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    mov currentHash, 0A312280Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    mov currentHash, 039012389h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    mov currentHash, 01E232287h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    mov currentHash, 003961D26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    mov currentHash, 093379F9Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    mov currentHash, 08F38AF73h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    mov currentHash, 0E4413D0Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    mov currentHash, 0DD4D283Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    mov currentHash, 0FA4C3A1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    mov currentHash, 03C087126h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    mov currentHash, 0605C2171h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsUILanguageComitted ENDP

NtListenPort PROC
    mov currentHash, 060B36F30h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListenPort ENDP

NtLoadDriver PROC
    mov currentHash, 0F15E28F5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    mov currentHash, 02281B4B4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    mov currentHash, 0928019A3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadHotPatch ENDP

NtLoadKey PROC
    mov currentHash, 06ED28DA9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey ENDP

NtLoadKey2 PROC
    mov currentHash, 0C7BC115Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    mov currentHash, 0157AC126h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKeyEx ENDP

NtLockFile PROC
    mov currentHash, 02883E127h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockFile ENDP

NtLockProductActivationKeys PROC
    mov currentHash, 0AE34A5A1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    mov currentHash, 02726C23Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    mov currentHash, 0C44CCECCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    mov currentHash, 074AF7433h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    mov currentHash, 0FAA301CCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    mov currentHash, 03A8C5A5Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManagePartition ENDP

NtMapCMFModule PROC
    mov currentHash, 0B4DC9E4Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    mov currentHash, 08DBEBE3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    mov currentHash, 058D31614h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    mov currentHash, 067F44350h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    mov currentHash, 00998273Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    mov currentHash, 00C343AACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    mov currentHash, 0AA98F44Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    mov currentHash, 069F1524Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    mov currentHash, 026BA2B39h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    mov currentHash, 0438B2358h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    mov currentHash, 0311170FBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    mov currentHash, 08632625Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    mov currentHash, 0B52055B2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    mov currentHash, 006BA2C07h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    mov currentHash, 0ADA6E373h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    mov currentHash, 0C369F3B5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    mov currentHash, 0C2DCF462h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    mov currentHash, 038BA00FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    mov currentHash, 02E80491Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    mov currentHash, 02EAB0A7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    mov currentHash, 036AED5BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    mov currentHash, 006B62935h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    mov currentHash, 00997010Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    mov currentHash, 0009A020Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    mov currentHash, 0F1B1DF6Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    mov currentHash, 04B5A1264h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSemaphore ENDP

NtOpenSession PROC
    mov currentHash, 00F940F06h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    mov currentHash, 03886063Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    mov currentHash, 0785C7AF5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtOpenTimer PROC
    mov currentHash, 03590371Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTimer ENDP

NtOpenTransaction PROC
    mov currentHash, 0B2AC51FCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    mov currentHash, 009B3715Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    mov currentHash, 0F066DCA6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    mov currentHash, 048B5A6E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    mov currentHash, 039A5382Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    mov currentHash, 0B531A4BDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    mov currentHash, 08AB5AF03h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    mov currentHash, 0CA55E3C9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    mov currentHash, 0DC52D2CAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    mov currentHash, 0DAA5F27Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    mov currentHash, 03EA5D729h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationComplete ENDP

NtPropagationFailed PROC
    mov currentHash, 0CA98D225h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationFailed ENDP

NtPulseEvent PROC
    mov currentHash, 01B0A7C90h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    mov currentHash, 099BD9C3Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    mov currentHash, 0A01C7936h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    mov currentHash, 04FDB7741h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    mov currentHash, 09E01F88Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    mov currentHash, 08AB84DE6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    mov currentHash, 06CBC6621h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    mov currentHash, 0633CBA97h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    mov currentHash, 035637BC6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    mov currentHash, 0D841C6E4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    mov currentHash, 075256BA4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    mov currentHash, 03AA210E5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    mov currentHash, 01B9AFFF1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    mov currentHash, 03AA43409h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    mov currentHash, 07CB61924h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    mov currentHash, 002B3F7D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    mov currentHash, 006CE261Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    mov currentHash, 00C36C46Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    mov currentHash, 00E9AF7DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    mov currentHash, 0FB4CE0F0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    mov currentHash, 0291E23B8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    mov currentHash, 0248FA49Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    mov currentHash, 040DB0F10h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    mov currentHash, 08185A23Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    mov currentHash, 02EFA6F2Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    mov currentHash, 0B1D4A4B2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    mov currentHash, 09765CBB0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    mov currentHash, 061BD09A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    mov currentHash, 0E677AC50h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    mov currentHash, 07DD7A47Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    mov currentHash, 005BD4F62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    mov currentHash, 096A1ABE5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    mov currentHash, 0C511B7B7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    mov currentHash, 01405FC79h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    mov currentHash, 01632F53Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    mov currentHash, 0E3083E5Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    mov currentHash, 09092C44Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    mov currentHash, 048D02E05h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    mov currentHash, 05B1DA140h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    mov currentHash, 00E982C0Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    mov currentHash, 08AAAAC15h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    mov currentHash, 01C3CF56Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseException ENDP

NtRaiseHardError PROC
    mov currentHash, 001F10563h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    mov currentHash, 03867CA21h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    mov currentHash, 061D89ABFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    mov currentHash, 03FA95770h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    mov currentHash, 013228123h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    mov currentHash, 0654DE663h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    mov currentHash, 05CB05938h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    mov currentHash, 08921AEB3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    mov currentHash, 0F851EEF5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    mov currentHash, 05AD26767h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    mov currentHash, 0463B0BF0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    mov currentHash, 097CCA460h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameKey ENDP

NtRenameTransactionManager PROC
    mov currentHash, 03E262CA6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    mov currentHash, 089D2BE63h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    mov currentHash, 016AB3E30h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    mov currentHash, 0A435ABAEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    mov currentHash, 022B258BCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestPort ENDP

NtResetEvent PROC
    mov currentHash, 08ED58946h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetEvent ENDP

NtResetWriteWatch PROC
    mov currentHash, 03CA8464Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetWriteWatch ENDP

NtRestoreKey PROC
    mov currentHash, 07BBE9BD5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRestoreKey ENDP

NtResumeProcess PROC
    mov currentHash, 04FA5483Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    mov currentHash, 00E90CCC3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    mov currentHash, 02F540BD4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    mov currentHash, 0B7ABB221h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    mov currentHash, 0C8922E02h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    mov currentHash, 0004BC61Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    mov currentHash, 0AE329C8Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    mov currentHash, 0AB989C26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKey ENDP

NtSaveKeyEx PROC
    mov currentHash, 0B5B9FD78h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    mov currentHash, 0EE55F9DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    mov currentHash, 0E90CE293h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    mov currentHash, 070206AAFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    mov currentHash, 03F5CAD71h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    mov currentHash, 09D89D750h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    mov currentHash, 00AC0285Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    mov currentHash, 054CADE0Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    mov currentHash, 008A87A01h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    mov currentHash, 03E1DEF21h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    mov currentHash, 05CCE5960h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    mov currentHash, 0519A6FCBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    mov currentHash, 0189A0A27h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    mov currentHash, 007A83CE5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    mov currentHash, 0A2FA64A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEaFile ENDP

NtSetHighEventPair PROC
    mov currentHash, 024B00C05h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    mov currentHash, 023B13A26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    mov currentHash, 021A23322h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    mov currentHash, 0EE33E6AFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    mov currentHash, 007A81C3Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    mov currentHash, 014B80615h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    mov currentHash, 03CD83F43h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    mov currentHash, 095A364A7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    mov currentHash, 0D847D6D6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    mov currentHash, 01E50914Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    mov currentHash, 0C996C938h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    mov currentHash, 04FD34148h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    mov currentHash, 03BAB373Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    mov currentHash, 088179E7Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    mov currentHash, 02DB9D43Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    mov currentHash, 09AD0BA05h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    mov currentHash, 0D6D4048Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    mov currentHash, 0EC8E3621h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    mov currentHash, 082D18A4Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    mov currentHash, 010B43029h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    mov currentHash, 08536CBE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    mov currentHash, 00D1F6986h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    mov currentHash, 0B8DE9D5Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    mov currentHash, 0BF81FD54h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    mov currentHash, 02441D522h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    mov currentHash, 0708386CAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    mov currentHash, 0B435FFE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    mov currentHash, 0EE4DC8C4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    mov currentHash, 057D4F08Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer2 ENDP

NtSetTimerEx PROC
    mov currentHash, 00E84D426h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    mov currentHash, 00E902FDFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    mov currentHash, 04862C14Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    mov currentHash, 0B238260Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    mov currentHash, 09012F98Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    mov currentHash, 00E5DD1EDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    mov currentHash, 04494762Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    mov currentHash, 0253F2DA2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    mov currentHash, 016BD2E11h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSinglePhaseReject ENDP

NtStartProfile PROC
    mov currentHash, 0EFB9C72Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartProfile ENDP

NtStopProfile PROC
    mov currentHash, 0CB9B003Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    mov currentHash, 082C35F7Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    mov currentHash, 01DA1042Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 02C9F220Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtSystemDebugControl PROC
    mov currentHash, 0876885FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    mov currentHash, 0BA2998A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    mov currentHash, 020780925h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateJobObject ENDP

NtTestAlert PROC
    mov currentHash, 08C27A582h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtThawRegistry PROC
    mov currentHash, 01083180Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawRegistry ENDP

NtThawTransactions PROC
    mov currentHash, 03BEF7F25h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawTransactions ENDP

NtTraceControl PROC
    mov currentHash, 0DC8ED816h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceControl ENDP

NtTranslateFilePath PROC
    mov currentHash, 08798B016h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    mov currentHash, 0E7B8EC1Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    mov currentHash, 0EAC7F36Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadDriver ENDP

NtUnloadKey PROC
    mov currentHash, 01DCDFFB6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey ENDP

NtUnloadKey2 PROC
    mov currentHash, 0ABD0440Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    mov currentHash, 0F4783506h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    mov currentHash, 0A13C9DBDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    mov currentHash, 073E2677Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    mov currentHash, 0D28901D3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    mov currentHash, 036A710FAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    mov currentHash, 062BD8CF0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    mov currentHash, 0DD8CF356h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    mov currentHash, 08C505AEAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    mov currentHash, 0715A42FCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    mov currentHash, 048CB4B5Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    mov currentHash, 0E28E1BFFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    mov currentHash, 010983409h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    mov currentHash, 02F01AD16h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    mov currentHash, 02893B1BAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    mov currentHash, 08D13A98Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    mov currentHash, 0C51B81C8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    mov currentHash, 08873BAD7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    mov currentHash, 01AB33C23h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    mov currentHash, 0E670989Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    mov currentHash, 004C92202h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    mov currentHash, 00096F5EBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    mov currentHash, 03EBB5968h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    mov currentHash, 010C83D68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    mov currentHash, 05BC73D13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListTransactions ENDP

NtMarshallTransaction PROC
    mov currentHash, 0014A2217h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMarshallTransaction ENDP

NtPullTransaction PROC
    mov currentHash, 0F7AFD1E7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    mov currentHash, 07AAD7A3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    mov currentHash, 039A9FAFFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    mov currentHash, 021AC7B02h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartTm ENDP

NtSetInformationProcess PROC
    mov currentHash, 08A2A95BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    mov currentHash, 09B389FACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    mov currentHash, 002B66946h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    mov currentHash, 0B52F9EBEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    mov currentHash, 07E423460h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManageHotPatch ENDP

NtContinueEx PROC
    mov currentHash, 0138F4354h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinueEx ENDP

end