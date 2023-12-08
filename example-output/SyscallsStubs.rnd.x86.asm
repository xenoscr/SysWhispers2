.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data
stubReturn      dd 0
returnAddress   dd 0
espBookmark     dd 0
syscallNumber   dd 0
syscallAddress  dd 0

.code

EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC

WhisperMain PROC
    pop eax                                 ; Remove return address from CALL instruction
    mov dword ptr [stubReturn], eax         ; Save the return address to the stub
    push esp
    pop eax
    add eax, 04h
    push dword ptr [eax]
    pop returnAddress                       ; Save the original return address
    add eax, 04h
    push eax
    pop espBookmark                         ; Save original ESP
    call SW2_GetSyscallNumber               ; Resolve function hash into syscall number
    add esp, 4                              ; Restore ESP
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor eax, eax
    mov ecx, fs:[0c0h]
    test ecx, ecx
    je _x86
    inc eax
_x86: 
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+04h]
    call SW2_GetRandomSyscallAddress        ; Get a memory address of random syscall
    mov dword ptr [syscallAddress], eax     ; Save the address
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    mov eax, dword ptr [syscallNumber]      ; Restore the syscall number
    call dword ptr syscallAddress           ; Call the random syscall
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    push dword ptr [returnAddress]          ; Restore the return address
    ret
WhisperMain ENDP

NtAccessCheck PROC
    push 02C9E332Bh
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 003A27F57h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 02AB5391Ah
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 08E649A02h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 0F559E2DAh
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 06CF64F62h
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 066B86A12h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 025BCAE9Dh
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 0CCFB8428h
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 01F027FD0h
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 0F4181198h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 020B20926h
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 06EF06368h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 06B5473F7h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 07EE44768h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 094944D26h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 09CBC67D0h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 078DE6158h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 08ADEA579h
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 01E1A0189h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 0D646D7D4h
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 001204DF4h
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 059ED7852h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 01930F45Ah
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 00F812137h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 0812484ACh
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 07CEE7C39h
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 05FCE7517h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 04A0365A0h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 03B952177h
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 034B93726h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 0BA0387A2h
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 013A881ACh
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 0DAB42FD5h
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 01F930501h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 079D2734Ah
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 01C0BD6BDh
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0412944B0h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 023244E22h
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 0D64FF69Dh
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 019BF1321h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 03AD21C5Bh
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0BB95EF49h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 0C1E25400h
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 0C49F3EF3h
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 017AC232Fh
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 0029BD4C5h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 0989ADE24h
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 0F9751426h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 04B3E6A96h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0D691DC26h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 004961FE3h
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 060BA6202h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 09C33BCA1h
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 0F4EF17F2h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0EA5AE4D9h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 0303B2989h
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 00595031Bh
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 0923594A0h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 00EA6E68Dh
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0E670E6EAh
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 0A0B3A925h
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 00D961311h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 0D9732600h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 0A1A53085h
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 005309710h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0BF16AA99h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 09331CF0Ah
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 00830469Ah
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 0FC4FBAFBh
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 024760726h
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 01A3C9C2Eh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 0A1274927h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 0E30CE39Ah
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 02FBCF185h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 00B5E7B8Dh
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 09F95D341h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 0248F3E30h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 0D4ADDE06h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 041AC3D5Bh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 00F4C03EFh
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 0E2806CA1h
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 00EAE5467h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0A20A7A30h
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 0ABBA21ADh
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 01EDBF680h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 05C92A8C0h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 08897EA68h
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 092345460h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0339D4373h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 08AA679AAh
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 05AC36C5Eh
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 0BE08A4AEh
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 08F126A00h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 00F9AE984h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 01BA78EA3h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 043975514h
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 01CDA026Eh
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 0A33B2326h
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 014CA96D6h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 068353E06h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 052DF4F46h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 0AB50F7B5h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 009981900h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 011980110h
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 005D1591Ch
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 0871C8385h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 015AF5106h
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 0102F9E05h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 040B96E7Ah
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 093BB581Ch
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 0173561B7h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 089A2A018h
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 02DF55339h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 0A0B61C93h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 0E572FAE1h
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 03395420Eh
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 01E8D0700h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 0118C5F4Bh
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 03EB22B3Ah
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 004D90C43h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 040D2B05Fh
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 0AB358F6Eh
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 010AEE4E6h
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0D841C6CDh
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 0F65AA863h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 030903503h
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 016820512h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 0653163ABh
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 0AEA2D323h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 021B23C3Bh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0622253A0h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 0148FD1A6h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 0089E2A13h
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 0EDCDB872h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 07762820Bh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 022B3012Ch
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 04EDB684Bh
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 01DB34B8Eh
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 08A99FA65h
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 09CB98A24h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 0552A302Ah
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 0069CB4A6h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 03B98BA82h
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 0B8BC74ADh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0782278BEh
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 038C00C6Ah
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 0F044EDD6h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 004932405h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 092D55F8Eh
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 0FB80EC2Ah
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 09FD369BFh
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 014CA7C2Eh
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 04DD06B0Bh
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 058F3BB9Ch
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 025DD2042h
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 0E671FDDEh
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 06DD6BE97h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 0943BA083h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 07AD43439h
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 04CEB143Ah
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 09B39BE73h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 0DE52E7E4h
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 040934C0Dh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 02491D0EBh
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 03C9B1C15h
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 00DB1E7AFh
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 0B03EEA91h
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 018C94276h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 030B41928h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 0CF91C202h
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 04E91A0DAh
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0723577A3h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 022252282h
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 00E814C24h
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 0BEA7D03Bh
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 0AFBDD24Dh
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 06CD612C5h
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 0379C3806h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 0C89BC821h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 002BBC5E5h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 052CC7019h
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 04D97553Ah
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 09B0AEFE3h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 00E987251h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 092BEDC68h
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 01F9BEA10h
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 00F84835Ah
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 00F99E602h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 06784BBC0h
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 03ACADB59h
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 0042E3CA4h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0872D9F40h
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0BC9A96C4h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 024F8AEE6h
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0B7109850h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 001561FD0h
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 0E343C0EDh
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 07D074CB4h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 035BBD4A9h
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 00195F4EBh
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 019966F68h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 03D3C2A80h
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 0665B11A0h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 012B41E2Ah
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 02D0D36ADh
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 03A2F1598h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 08E877890h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 0746AEB51h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 02FB8B58Eh
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 00C90C0C5h
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0F74EC0E5h
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 0F82EEE87h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 0E45CC1C3h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 03C8C4D6Fh
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0B34A85F7h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 084A867D4h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 000CB3E67h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 09405F6D9h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 003117798h
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 07489A8DCh
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 0D6260C84h
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 0FDCACE96h
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 00D334E15h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 0152778D4h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 002D882C0h
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 04390356Fh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 003BF6B65h
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 0F74DD4F2h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 0F0AD35E0h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 00792D5D5h
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 0BEFAB868h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 04E864A1Fh
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 018B0420Dh
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 0143368D9h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 066EAA155h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 0623D946Ch
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 086059C8Fh
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 041DB4254h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 01409DF26h
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 0A312280Ah
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 039012389h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 01E232287h
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 003961D26h
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 093379F9Eh
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 08F38AF73h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 0E4413D0Eh
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0DD4D283Eh
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0FA4C3A1Fh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 03C087126h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 0605C2171h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 060B36F30h
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 0F15E28F5h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 02281B4B4h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 0928019A3h
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 06ED28DA9h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 0C7BC115Ch
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 0157AC126h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 02883E127h
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 0AE34A5A1h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 02726C23Ah
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 0C44CCECCh
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 074AF7433h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 0FAA301CCh
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 03A8C5A5Bh
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 0B4DC9E4Bh
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 08DBEBE3Ah
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 058D31614h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 067F44350h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 00998273Eh
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 00C343AACh
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 0AA98F44Fh
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 069F1524Ch
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 026BA2B39h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 0438B2358h
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 0311170FBh
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 08632625Fh
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 0B52055B2h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 006BA2C07h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 0ADA6E373h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0C369F3B5h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 0C2DCF462h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 038BA00FEh
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 02E80491Ah
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 02EAB0A7Ch
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 036AED5BBh
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 006B62935h
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 00997010Eh
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 0009A020Bh
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 0F1B1DF6Dh
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 04B5A1264h
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 00F940F06h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 03886063Bh
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0785C7AF5h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 03590371Ch
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 0B2AC51FCh
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 009B3715Eh
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0F066DCA6h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 048B5A6E6h
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 039A5382Fh
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 0B531A4BDh
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 08AB5AF03h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 0CA55E3C9h
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 0DC52D2CAh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 0DAA5F27Ah
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 03EA5D729h
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 0CA98D225h
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 01B0A7C90h
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 099BD9C3Eh
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 0A01C7936h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 04FDB7741h
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 09E01F88Ch
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 08AB84DE6h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 06CBC6621h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0633CBA97h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 035637BC6h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 0D841C6E4h
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 075256BA4h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 03AA210E5h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 01B9AFFF1h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 03AA43409h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 07CB61924h
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 002B3F7D0h
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 006CE261Dh
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 00C36C46Ch
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 00E9AF7DBh
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 0FB4CE0F0h
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0291E23B8h
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 0248FA49Dh
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 040DB0F10h
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 08185A23Fh
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 02EFA6F2Eh
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 0B1D4A4B2h
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 09765CBB0h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 061BD09A0h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0E677AC50h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 07DD7A47Ch
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 005BD4F62h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 096A1ABE5h
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 0C511B7B7h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 01405FC79h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 01632F53Ah
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 0E3083E5Dh
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 09092C44Eh
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 048D02E05h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 05B1DA140h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 00E982C0Dh
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 08AAAAC15h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 01C3CF56Ch
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 001F10563h
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 03867CA21h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 061D89ABFh
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 03FA95770h
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 013228123h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 0654DE663h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 05CB05938h
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 08921AEB3h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 0F851EEF5h
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 05AD26767h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 0463B0BF0h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 097CCA460h
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 03E262CA6h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 089D2BE63h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 016AB3E30h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 0A435ABAEh
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 022B258BCh
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 08ED58946h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 03CA8464Ah
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 07BBE9BD5h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 04FA5483Eh
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 00E90CCC3h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 02F540BD4h
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 0B7ABB221h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 0C8922E02h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 0004BC61Bh
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 0AE329C8Fh
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 0AB989C26h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 0B5B9FD78h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 0EE55F9DFh
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 0E90CE293h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 070206AAFh
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 03F5CAD71h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 09D89D750h
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 00AC0285Eh
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 054CADE0Eh
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 008A87A01h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 03E1DEF21h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 05CCE5960h
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0519A6FCBh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0189A0A27h
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 007A83CE5h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 0A2FA64A6h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 024B00C05h
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 023B13A26h
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 021A23322h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 0EE33E6AFh
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 007A81C3Fh
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 014B80615h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 03CD83F43h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 095A364A7h
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 0D847D6D6h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 01E50914Eh
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 0C996C938h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 04FD34148h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 03BAB373Fh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 088179E7Ah
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 02DB9D43Dh
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 09AD0BA05h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 0D6D4048Eh
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 0EC8E3621h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 082D18A4Ah
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 010B43029h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 08536CBE3h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 00D1F6986h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 0B8DE9D5Eh
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 0BF81FD54h
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 02441D522h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 0708386CAh
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 0B435FFE3h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 0EE4DC8C4h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 057D4F08Dh
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 00E84D426h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 00E902FDFh
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 04862C14Fh
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 0B238260Eh
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 09012F98Eh
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 00E5DD1EDh
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 04494762Ch
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 0253F2DA2h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 016BD2E11h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 0EFB9C72Ch
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0CB9B003Dh
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 082C35F7Bh
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 01DA1042Ch
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 02C9F220Dh
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0876885FDh
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0BA2998A0h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 020780925h
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 08C27A582h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 01083180Dh
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 03BEF7F25h
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 0DC8ED816h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 08798B016h
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 0E7B8EC1Eh
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 0EAC7F36Ch
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 01DCDFFB6h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0ABD0440Dh
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 0F4783506h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 0A13C9DBDh
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 073E2677Dh
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 0D28901D3h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 036A710FAh
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 062BD8CF0h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 0DD8CF356h
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 08C505AEAh
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 0715A42FCh
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 048CB4B5Ch
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0E28E1BFFh
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 010983409h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 02F01AD16h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 02893B1BAh
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 08D13A98Ch
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 0C51B81C8h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 08873BAD7h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 01AB33C23h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 0E670989Dh
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 004C92202h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 00096F5EBh
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 03EBB5968h
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 010C83D68h
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 05BC73D13h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 0014A2217h
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0F7AFD1E7h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 07AAD7A3Ah
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 039A9FAFFh
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 021AC7B02h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 08A2A95BBh
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 09B389FACh
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 002B66946h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0B52F9EBEh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 07E423460h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 0138F4354h
    call WhisperMain
NtContinueEx ENDP

end