[SECTION .data align=4]
stubReturn:     dd  0
returnAddress:  dd  0
espBookmark:    dd  0
syscallNumber:  dd  0
syscallAddress: dd  0

[SECTION .text]

BITS 32
DEFAULT REL

global _NtAccessCheck
global _NtWorkerFactoryWorkerReady
global _NtAcceptConnectPort
global _NtMapUserPhysicalPagesScatter
global _NtWaitForSingleObject
global _NtCallbackReturn
global _NtReadFile
global _NtDeviceIoControlFile
global _NtWriteFile
global _NtRemoveIoCompletion
global _NtReleaseSemaphore
global _NtReplyWaitReceivePort
global _NtReplyPort
global _NtSetInformationThread
global _NtSetEvent
global _NtClose
global _NtQueryObject
global _NtQueryInformationFile
global _NtOpenKey
global _NtEnumerateValueKey
global _NtFindAtom
global _NtQueryDefaultLocale
global _NtQueryKey
global _NtQueryValueKey
global _NtAllocateVirtualMemory
global _NtQueryInformationProcess
global _NtWaitForMultipleObjects32
global _NtWriteFileGather
global _NtCreateKey
global _NtFreeVirtualMemory
global _NtImpersonateClientOfPort
global _NtReleaseMutant
global _NtQueryInformationToken
global _NtRequestWaitReplyPort
global _NtQueryVirtualMemory
global _NtOpenThreadToken
global _NtQueryInformationThread
global _NtOpenProcess
global _NtSetInformationFile
global _NtMapViewOfSection
global _NtAccessCheckAndAuditAlarm
global _NtUnmapViewOfSection
global _NtReplyWaitReceivePortEx
global _NtTerminateProcess
global _NtSetEventBoostPriority
global _NtReadFileScatter
global _NtOpenThreadTokenEx
global _NtOpenProcessTokenEx
global _NtQueryPerformanceCounter
global _NtEnumerateKey
global _NtOpenFile
global _NtDelayExecution
global _NtQueryDirectoryFile
global _NtQuerySystemInformation
global _NtOpenSection
global _NtQueryTimer
global _NtFsControlFile
global _NtWriteVirtualMemory
global _NtCloseObjectAuditAlarm
global _NtDuplicateObject
global _NtQueryAttributesFile
global _NtClearEvent
global _NtReadVirtualMemory
global _NtOpenEvent
global _NtAdjustPrivilegesToken
global _NtDuplicateToken
global _NtContinue
global _NtQueryDefaultUILanguage
global _NtQueueApcThread
global _NtYieldExecution
global _NtAddAtom
global _NtCreateEvent
global _NtQueryVolumeInformationFile
global _NtCreateSection
global _NtFlushBuffersFile
global _NtApphelpCacheControl
global _NtCreateProcessEx
global _NtCreateThread
global _NtIsProcessInJob
global _NtProtectVirtualMemory
global _NtQuerySection
global _NtResumeThread
global _NtTerminateThread
global _NtReadRequestData
global _NtCreateFile
global _NtQueryEvent
global _NtWriteRequestData
global _NtOpenDirectoryObject
global _NtAccessCheckByTypeAndAuditAlarm
global _NtWaitForMultipleObjects
global _NtSetInformationObject
global _NtCancelIoFile
global _NtTraceEvent
global _NtPowerInformation
global _NtSetValueKey
global _NtCancelTimer
global _NtSetTimer
global _NtAccessCheckByType
global _NtAccessCheckByTypeResultList
global _NtAccessCheckByTypeResultListAndAuditAlarm
global _NtAccessCheckByTypeResultListAndAuditAlarmByHandle
global _NtAcquireProcessActivityReference
global _NtAddAtomEx
global _NtAddBootEntry
global _NtAddDriverEntry
global _NtAdjustGroupsToken
global _NtAdjustTokenClaimsAndDeviceGroups
global _NtAlertResumeThread
global _NtAlertThread
global _NtAlertThreadByThreadId
global _NtAllocateLocallyUniqueId
global _NtAllocateReserveObject
global _NtAllocateUserPhysicalPages
global _NtAllocateUuids
global _NtAllocateVirtualMemoryEx
global _NtAlpcAcceptConnectPort
global _NtAlpcCancelMessage
global _NtAlpcConnectPort
global _NtAlpcConnectPortEx
global _NtAlpcCreatePort
global _NtAlpcCreatePortSection
global _NtAlpcCreateResourceReserve
global _NtAlpcCreateSectionView
global _NtAlpcCreateSecurityContext
global _NtAlpcDeletePortSection
global _NtAlpcDeleteResourceReserve
global _NtAlpcDeleteSectionView
global _NtAlpcDeleteSecurityContext
global _NtAlpcDisconnectPort
global _NtAlpcImpersonateClientContainerOfPort
global _NtAlpcImpersonateClientOfPort
global _NtAlpcOpenSenderProcess
global _NtAlpcOpenSenderThread
global _NtAlpcQueryInformation
global _NtAlpcQueryInformationMessage
global _NtAlpcRevokeSecurityContext
global _NtAlpcSendWaitReceivePort
global _NtAlpcSetInformation
global _NtAreMappedFilesTheSame
global _NtAssignProcessToJobObject
global _NtAssociateWaitCompletionPacket
global _NtCallEnclave
global _NtCancelIoFileEx
global _NtCancelSynchronousIoFile
global _NtCancelTimer2
global _NtCancelWaitCompletionPacket
global _NtCommitComplete
global _NtCommitEnlistment
global _NtCommitRegistryTransaction
global _NtCommitTransaction
global _NtCompactKeys
global _NtCompareObjects
global _NtCompareSigningLevels
global _NtCompareTokens
global _NtCompleteConnectPort
global _NtCompressKey
global _NtConnectPort
global _NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
global _NtCreateDebugObject
global _NtCreateDirectoryObject
global _NtCreateDirectoryObjectEx
global _NtCreateEnclave
global _NtCreateEnlistment
global _NtCreateEventPair
global _NtCreateIRTimer
global _NtCreateIoCompletion
global _NtCreateJobObject
global _NtCreateJobSet
global _NtCreateKeyTransacted
global _NtCreateKeyedEvent
global _NtCreateLowBoxToken
global _NtCreateMailslotFile
global _NtCreateMutant
global _NtCreateNamedPipeFile
global _NtCreatePagingFile
global _NtCreatePartition
global _NtCreatePort
global _NtCreatePrivateNamespace
global _NtCreateProcess
global _NtCreateProfile
global _NtCreateProfileEx
global _NtCreateRegistryTransaction
global _NtCreateResourceManager
global _NtCreateSemaphore
global _NtCreateSymbolicLinkObject
global _NtCreateThreadEx
global _NtCreateTimer
global _NtCreateTimer2
global _NtCreateToken
global _NtCreateTokenEx
global _NtCreateTransaction
global _NtCreateTransactionManager
global _NtCreateUserProcess
global _NtCreateWaitCompletionPacket
global _NtCreateWaitablePort
global _NtCreateWnfStateName
global _NtCreateWorkerFactory
global _NtDebugActiveProcess
global _NtDebugContinue
global _NtDeleteAtom
global _NtDeleteBootEntry
global _NtDeleteDriverEntry
global _NtDeleteFile
global _NtDeleteKey
global _NtDeleteObjectAuditAlarm
global _NtDeletePrivateNamespace
global _NtDeleteValueKey
global _NtDeleteWnfStateData
global _NtDeleteWnfStateName
global _NtDisableLastKnownGood
global _NtDisplayString
global _NtDrawText
global _NtEnableLastKnownGood
global _NtEnumerateBootEntries
global _NtEnumerateDriverEntries
global _NtEnumerateSystemEnvironmentValuesEx
global _NtEnumerateTransactionObject
global _NtExtendSection
global _NtFilterBootOption
global _NtFilterToken
global _NtFilterTokenEx
global _NtFlushBuffersFileEx
global _NtFlushInstallUILanguage
global _NtFlushInstructionCache
global _NtFlushKey
global _NtFlushProcessWriteBuffers
global _NtFlushVirtualMemory
global _NtFlushWriteBuffer
global _NtFreeUserPhysicalPages
global _NtFreezeRegistry
global _NtFreezeTransactions
global _NtGetCachedSigningLevel
global _NtGetCompleteWnfStateSubscription
global _NtGetContextThread
global _NtGetCurrentProcessorNumber
global _NtGetCurrentProcessorNumberEx
global _NtGetDevicePowerState
global _NtGetMUIRegistryInfo
global _NtGetNextProcess
global _NtGetNextThread
global _NtGetNlsSectionPtr
global _NtGetNotificationResourceManager
global _NtGetWriteWatch
global _NtImpersonateAnonymousToken
global _NtImpersonateThread
global _NtInitializeEnclave
global _NtInitializeNlsFiles
global _NtInitializeRegistry
global _NtInitiatePowerAction
global _NtIsSystemResumeAutomatic
global _NtIsUILanguageComitted
global _NtListenPort
global _NtLoadDriver
global _NtLoadEnclaveData
global _NtLoadHotPatch
global _NtLoadKey
global _NtLoadKey2
global _NtLoadKeyEx
global _NtLockFile
global _NtLockProductActivationKeys
global _NtLockRegistryKey
global _NtLockVirtualMemory
global _NtMakePermanentObject
global _NtMakeTemporaryObject
global _NtManagePartition
global _NtMapCMFModule
global _NtMapUserPhysicalPages
global _NtMapViewOfSectionEx
global _NtModifyBootEntry
global _NtModifyDriverEntry
global _NtNotifyChangeDirectoryFile
global _NtNotifyChangeDirectoryFileEx
global _NtNotifyChangeKey
global _NtNotifyChangeMultipleKeys
global _NtNotifyChangeSession
global _NtOpenEnlistment
global _NtOpenEventPair
global _NtOpenIoCompletion
global _NtOpenJobObject
global _NtOpenKeyEx
global _NtOpenKeyTransacted
global _NtOpenKeyTransactedEx
global _NtOpenKeyedEvent
global _NtOpenMutant
global _NtOpenObjectAuditAlarm
global _NtOpenPartition
global _NtOpenPrivateNamespace
global _NtOpenProcessToken
global _NtOpenRegistryTransaction
global _NtOpenResourceManager
global _NtOpenSemaphore
global _NtOpenSession
global _NtOpenSymbolicLinkObject
global _NtOpenThread
global _NtOpenTimer
global _NtOpenTransaction
global _NtOpenTransactionManager
global _NtPlugPlayControl
global _NtPrePrepareComplete
global _NtPrePrepareEnlistment
global _NtPrepareComplete
global _NtPrepareEnlistment
global _NtPrivilegeCheck
global _NtPrivilegeObjectAuditAlarm
global _NtPrivilegedServiceAuditAlarm
global _NtPropagationComplete
global _NtPropagationFailed
global _NtPulseEvent
global _NtQueryAuxiliaryCounterFrequency
global _NtQueryBootEntryOrder
global _NtQueryBootOptions
global _NtQueryDebugFilterState
global _NtQueryDirectoryFileEx
global _NtQueryDirectoryObject
global _NtQueryDriverEntryOrder
global _NtQueryEaFile
global _NtQueryFullAttributesFile
global _NtQueryInformationAtom
global _NtQueryInformationByName
global _NtQueryInformationEnlistment
global _NtQueryInformationJobObject
global _NtQueryInformationPort
global _NtQueryInformationResourceManager
global _NtQueryInformationTransaction
global _NtQueryInformationTransactionManager
global _NtQueryInformationWorkerFactory
global _NtQueryInstallUILanguage
global _NtQueryIntervalProfile
global _NtQueryIoCompletion
global _NtQueryLicenseValue
global _NtQueryMultipleValueKey
global _NtQueryMutant
global _NtQueryOpenSubKeys
global _NtQueryOpenSubKeysEx
global _NtQueryPortInformationProcess
global _NtQueryQuotaInformationFile
global _NtQuerySecurityAttributesToken
global _NtQuerySecurityObject
global _NtQuerySecurityPolicy
global _NtQuerySemaphore
global _NtQuerySymbolicLinkObject
global _NtQuerySystemEnvironmentValue
global _NtQuerySystemEnvironmentValueEx
global _NtQuerySystemInformationEx
global _NtQueryTimerResolution
global _NtQueryWnfStateData
global _NtQueryWnfStateNameInformation
global _NtQueueApcThreadEx
global _NtRaiseException
global _NtRaiseHardError
global _NtReadOnlyEnlistment
global _NtRecoverEnlistment
global _NtRecoverResourceManager
global _NtRecoverTransactionManager
global _NtRegisterProtocolAddressInformation
global _NtRegisterThreadTerminatePort
global _NtReleaseKeyedEvent
global _NtReleaseWorkerFactoryWorker
global _NtRemoveIoCompletionEx
global _NtRemoveProcessDebug
global _NtRenameKey
global _NtRenameTransactionManager
global _NtReplaceKey
global _NtReplacePartitionUnit
global _NtReplyWaitReplyPort
global _NtRequestPort
global _NtResetEvent
global _NtResetWriteWatch
global _NtRestoreKey
global _NtResumeProcess
global _NtRevertContainerImpersonation
global _NtRollbackComplete
global _NtRollbackEnlistment
global _NtRollbackRegistryTransaction
global _NtRollbackTransaction
global _NtRollforwardTransactionManager
global _NtSaveKey
global _NtSaveKeyEx
global _NtSaveMergedKeys
global _NtSecureConnectPort
global _NtSerializeBoot
global _NtSetBootEntryOrder
global _NtSetBootOptions
global _NtSetCachedSigningLevel
global _NtSetCachedSigningLevel2
global _NtSetContextThread
global _NtSetDebugFilterState
global _NtSetDefaultHardErrorPort
global _NtSetDefaultLocale
global _NtSetDefaultUILanguage
global _NtSetDriverEntryOrder
global _NtSetEaFile
global _NtSetHighEventPair
global _NtSetHighWaitLowEventPair
global _NtSetIRTimer
global _NtSetInformationDebugObject
global _NtSetInformationEnlistment
global _NtSetInformationJobObject
global _NtSetInformationKey
global _NtSetInformationResourceManager
global _NtSetInformationSymbolicLink
global _NtSetInformationToken
global _NtSetInformationTransaction
global _NtSetInformationTransactionManager
global _NtSetInformationVirtualMemory
global _NtSetInformationWorkerFactory
global _NtSetIntervalProfile
global _NtSetIoCompletion
global _NtSetIoCompletionEx
global _NtSetLdtEntries
global _NtSetLowEventPair
global _NtSetLowWaitHighEventPair
global _NtSetQuotaInformationFile
global _NtSetSecurityObject
global _NtSetSystemEnvironmentValue
global _NtSetSystemEnvironmentValueEx
global _NtSetSystemInformation
global _NtSetSystemPowerState
global _NtSetSystemTime
global _NtSetThreadExecutionState
global _NtSetTimer2
global _NtSetTimerEx
global _NtSetTimerResolution
global _NtSetUuidSeed
global _NtSetVolumeInformationFile
global _NtSetWnfProcessNotificationEvent
global _NtShutdownSystem
global _NtShutdownWorkerFactory
global _NtSignalAndWaitForSingleObject
global _NtSinglePhaseReject
global _NtStartProfile
global _NtStopProfile
global _NtSubscribeWnfStateChange
global _NtSuspendProcess
global _NtSuspendThread
global _NtSystemDebugControl
global _NtTerminateEnclave
global _NtTerminateJobObject
global _NtTestAlert
global _NtThawRegistry
global _NtThawTransactions
global _NtTraceControl
global _NtTranslateFilePath
global _NtUmsThreadYield
global _NtUnloadDriver
global _NtUnloadKey
global _NtUnloadKey2
global _NtUnloadKeyEx
global _NtUnlockFile
global _NtUnlockVirtualMemory
global _NtUnmapViewOfSectionEx
global _NtUnsubscribeWnfStateChange
global _NtUpdateWnfStateData
global _NtVdmControl
global _NtWaitForAlertByThreadId
global _NtWaitForDebugEvent
global _NtWaitForKeyedEvent
global _NtWaitForWorkViaWorkerFactory
global _NtWaitHighEventPair
global _NtWaitLowEventPair
global _NtAcquireCMFViewOwnership
global _NtCancelDeviceWakeupRequest
global _NtClearAllSavepointsTransaction
global _NtClearSavepointTransaction
global _NtRollbackSavepointTransaction
global _NtSavepointTransaction
global _NtSavepointComplete
global _NtCreateSectionEx
global _NtCreateCrossVmEvent
global _NtGetPlugPlayEvent
global _NtListTransactions
global _NtMarshallTransaction
global _NtPullTransaction
global _NtReleaseCMFViewOwnership
global _NtWaitForWnfNotifications
global _NtStartTm
global _NtSetInformationProcess
global _NtRequestDeviceWakeup
global _NtRequestWakeupLatency
global _NtQuerySystemTime
global _NtManageHotPatch
global _NtContinueEx

global _WhisperMain
extern _SW2_GetSyscallNumber
extern _SW2_GetRandomSyscallAddress

_WhisperMain:
    pop eax                                  
    mov dword [stubReturn], eax             ; Save the return address to the stub
    push esp
    pop eax
    add eax, 4h
    push dword [eax]
    pop dword [returnAddress]               ; Save original return address
    add eax, 4h
    push eax
    pop dword [espBookmark]                 ; Save original ESP
    call _SW2_GetSyscallNumber              ; Resolve function hash into syscall number
    add esp, 4h                             ; Restore ESP
    mov dword [syscallNumber], eax          ; Save the syscall number
    xor eax, eax
    mov ecx, dword [fs:0c0h]
    test ecx, ecx
    je _x86
    inc eax                                 ; Inc EAX to 1 for Wow64
_x86:
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword [esp+4h]
    call _SW2_GetRandomSyscallAddress       ; Get a random 0x02E address
    mov dword [syscallAddress], eax         ; Save the address
    mov esp, dword [espBookmark]            ; Restore ESP
    mov eax, dword [syscallNumber]          ; Restore the syscall number
    call dword [syscallAddress]             ; Call the random syscall location
    mov esp, dword [espBookmark]            ; Restore ESP
    push dword [returnAddress]              ; Restore the return address
    ret
    
_NtAccessCheck:
    push 02C9E332Bh
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 003A27F57h
    call _WhisperMain

_NtAcceptConnectPort:
    push 02AB5391Ah
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 08E649A02h
    call _WhisperMain

_NtWaitForSingleObject:
    push 0F559E2DAh
    call _WhisperMain

_NtCallbackReturn:
    push 06CF64F62h
    call _WhisperMain

_NtReadFile:
    push 066B86A12h
    call _WhisperMain

_NtDeviceIoControlFile:
    push 025BCAE9Dh
    call _WhisperMain

_NtWriteFile:
    push 0CCFB8428h
    call _WhisperMain

_NtRemoveIoCompletion:
    push 01F027FD0h
    call _WhisperMain

_NtReleaseSemaphore:
    push 0F4181198h
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 020B20926h
    call _WhisperMain

_NtReplyPort:
    push 06EF06368h
    call _WhisperMain

_NtSetInformationThread:
    push 06B5473F7h
    call _WhisperMain

_NtSetEvent:
    push 07EE44768h
    call _WhisperMain

_NtClose:
    push 094944D26h
    call _WhisperMain

_NtQueryObject:
    push 09CBC67D0h
    call _WhisperMain

_NtQueryInformationFile:
    push 078DE6158h
    call _WhisperMain

_NtOpenKey:
    push 08ADEA579h
    call _WhisperMain

_NtEnumerateValueKey:
    push 01E1A0189h
    call _WhisperMain

_NtFindAtom:
    push 0D646D7D4h
    call _WhisperMain

_NtQueryDefaultLocale:
    push 001204DF4h
    call _WhisperMain

_NtQueryKey:
    push 059ED7852h
    call _WhisperMain

_NtQueryValueKey:
    push 01930F45Ah
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 00F812137h
    call _WhisperMain

_NtQueryInformationProcess:
    push 0812484ACh
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 07CEE7C39h
    call _WhisperMain

_NtWriteFileGather:
    push 05FCE7517h
    call _WhisperMain

_NtCreateKey:
    push 04A0365A0h
    call _WhisperMain

_NtFreeVirtualMemory:
    push 03B952177h
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 034B93726h
    call _WhisperMain

_NtReleaseMutant:
    push 0BA0387A2h
    call _WhisperMain

_NtQueryInformationToken:
    push 013A881ACh
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0DAB42FD5h
    call _WhisperMain

_NtQueryVirtualMemory:
    push 01F930501h
    call _WhisperMain

_NtOpenThreadToken:
    push 079D2734Ah
    call _WhisperMain

_NtQueryInformationThread:
    push 01C0BD6BDh
    call _WhisperMain

_NtOpenProcess:
    push 0412944B0h
    call _WhisperMain

_NtSetInformationFile:
    push 023244E22h
    call _WhisperMain

_NtMapViewOfSection:
    push 0D64FF69Dh
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 019BF1321h
    call _WhisperMain

_NtUnmapViewOfSection:
    push 03AD21C5Bh
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0BB95EF49h
    call _WhisperMain

_NtTerminateProcess:
    push 0C1E25400h
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0C49F3EF3h
    call _WhisperMain

_NtReadFileScatter:
    push 017AC232Fh
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0029BD4C5h
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0989ADE24h
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0F9751426h
    call _WhisperMain

_NtEnumerateKey:
    push 04B3E6A96h
    call _WhisperMain

_NtOpenFile:
    push 0D691DC26h
    call _WhisperMain

_NtDelayExecution:
    push 004961FE3h
    call _WhisperMain

_NtQueryDirectoryFile:
    push 060BA6202h
    call _WhisperMain

_NtQuerySystemInformation:
    push 09C33BCA1h
    call _WhisperMain

_NtOpenSection:
    push 0F4EF17F2h
    call _WhisperMain

_NtQueryTimer:
    push 0EA5AE4D9h
    call _WhisperMain

_NtFsControlFile:
    push 0303B2989h
    call _WhisperMain

_NtWriteVirtualMemory:
    push 00595031Bh
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0923594A0h
    call _WhisperMain

_NtDuplicateObject:
    push 00EA6E68Dh
    call _WhisperMain

_NtQueryAttributesFile:
    push 0E670E6EAh
    call _WhisperMain

_NtClearEvent:
    push 0A0B3A925h
    call _WhisperMain

_NtReadVirtualMemory:
    push 00D961311h
    call _WhisperMain

_NtOpenEvent:
    push 0D9732600h
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0A1A53085h
    call _WhisperMain

_NtDuplicateToken:
    push 005309710h
    call _WhisperMain

_NtContinue:
    push 0BF16AA99h
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 09331CF0Ah
    call _WhisperMain

_NtQueueApcThread:
    push 00830469Ah
    call _WhisperMain

_NtYieldExecution:
    push 0FC4FBAFBh
    call _WhisperMain

_NtAddAtom:
    push 024760726h
    call _WhisperMain

_NtCreateEvent:
    push 01A3C9C2Eh
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0A1274927h
    call _WhisperMain

_NtCreateSection:
    push 0E30CE39Ah
    call _WhisperMain

_NtFlushBuffersFile:
    push 02FBCF185h
    call _WhisperMain

_NtApphelpCacheControl:
    push 00B5E7B8Dh
    call _WhisperMain

_NtCreateProcessEx:
    push 09F95D341h
    call _WhisperMain

_NtCreateThread:
    push 0248F3E30h
    call _WhisperMain

_NtIsProcessInJob:
    push 0D4ADDE06h
    call _WhisperMain

_NtProtectVirtualMemory:
    push 041AC3D5Bh
    call _WhisperMain

_NtQuerySection:
    push 00F4C03EFh
    call _WhisperMain

_NtResumeThread:
    push 0E2806CA1h
    call _WhisperMain

_NtTerminateThread:
    push 00EAE5467h
    call _WhisperMain

_NtReadRequestData:
    push 0A20A7A30h
    call _WhisperMain

_NtCreateFile:
    push 0ABBA21ADh
    call _WhisperMain

_NtQueryEvent:
    push 01EDBF680h
    call _WhisperMain

_NtWriteRequestData:
    push 05C92A8C0h
    call _WhisperMain

_NtOpenDirectoryObject:
    push 08897EA68h
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 092345460h
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0339D4373h
    call _WhisperMain

_NtSetInformationObject:
    push 08AA679AAh
    call _WhisperMain

_NtCancelIoFile:
    push 05AC36C5Eh
    call _WhisperMain

_NtTraceEvent:
    push 0BE08A4AEh
    call _WhisperMain

_NtPowerInformation:
    push 08F126A00h
    call _WhisperMain

_NtSetValueKey:
    push 00F9AE984h
    call _WhisperMain

_NtCancelTimer:
    push 01BA78EA3h
    call _WhisperMain

_NtSetTimer:
    push 043975514h
    call _WhisperMain

_NtAccessCheckByType:
    push 01CDA026Eh
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0A33B2326h
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 014CA96D6h
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 068353E06h
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 052DF4F46h
    call _WhisperMain

_NtAddAtomEx:
    push 0AB50F7B5h
    call _WhisperMain

_NtAddBootEntry:
    push 009981900h
    call _WhisperMain

_NtAddDriverEntry:
    push 011980110h
    call _WhisperMain

_NtAdjustGroupsToken:
    push 005D1591Ch
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0871C8385h
    call _WhisperMain

_NtAlertResumeThread:
    push 015AF5106h
    call _WhisperMain

_NtAlertThread:
    push 0102F9E05h
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 040B96E7Ah
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 093BB581Ch
    call _WhisperMain

_NtAllocateReserveObject:
    push 0173561B7h
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 089A2A018h
    call _WhisperMain

_NtAllocateUuids:
    push 02DF55339h
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0A0B61C93h
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0E572FAE1h
    call _WhisperMain

_NtAlpcCancelMessage:
    push 03395420Eh
    call _WhisperMain

_NtAlpcConnectPort:
    push 01E8D0700h
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0118C5F4Bh
    call _WhisperMain

_NtAlpcCreatePort:
    push 03EB22B3Ah
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 004D90C43h
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 040D2B05Fh
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0AB358F6Eh
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 010AEE4E6h
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0D841C6CDh
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0F65AA863h
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 030903503h
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 016820512h
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0653163ABh
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0AEA2D323h
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 021B23C3Bh
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0622253A0h
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0148FD1A6h
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0089E2A13h
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0EDCDB872h
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 07762820Bh
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 022B3012Ch
    call _WhisperMain

_NtAlpcSetInformation:
    push 04EDB684Bh
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 01DB34B8Eh
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 08A99FA65h
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 09CB98A24h
    call _WhisperMain

_NtCallEnclave:
    push 0552A302Ah
    call _WhisperMain

_NtCancelIoFileEx:
    push 0069CB4A6h
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 03B98BA82h
    call _WhisperMain

_NtCancelTimer2:
    push 0B8BC74ADh
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0782278BEh
    call _WhisperMain

_NtCommitComplete:
    push 038C00C6Ah
    call _WhisperMain

_NtCommitEnlistment:
    push 0F044EDD6h
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 004932405h
    call _WhisperMain

_NtCommitTransaction:
    push 092D55F8Eh
    call _WhisperMain

_NtCompactKeys:
    push 0FB80EC2Ah
    call _WhisperMain

_NtCompareObjects:
    push 09FD369BFh
    call _WhisperMain

_NtCompareSigningLevels:
    push 014CA7C2Eh
    call _WhisperMain

_NtCompareTokens:
    push 04DD06B0Bh
    call _WhisperMain

_NtCompleteConnectPort:
    push 058F3BB9Ch
    call _WhisperMain

_NtCompressKey:
    push 025DD2042h
    call _WhisperMain

_NtConnectPort:
    push 0E671FDDEh
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 06DD6BE97h
    call _WhisperMain

_NtCreateDebugObject:
    push 0943BA083h
    call _WhisperMain

_NtCreateDirectoryObject:
    push 07AD43439h
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 04CEB143Ah
    call _WhisperMain

_NtCreateEnclave:
    push 09B39BE73h
    call _WhisperMain

_NtCreateEnlistment:
    push 0DE52E7E4h
    call _WhisperMain

_NtCreateEventPair:
    push 040934C0Dh
    call _WhisperMain

_NtCreateIRTimer:
    push 02491D0EBh
    call _WhisperMain

_NtCreateIoCompletion:
    push 03C9B1C15h
    call _WhisperMain

_NtCreateJobObject:
    push 00DB1E7AFh
    call _WhisperMain

_NtCreateJobSet:
    push 0B03EEA91h
    call _WhisperMain

_NtCreateKeyTransacted:
    push 018C94276h
    call _WhisperMain

_NtCreateKeyedEvent:
    push 030B41928h
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0CF91C202h
    call _WhisperMain

_NtCreateMailslotFile:
    push 04E91A0DAh
    call _WhisperMain

_NtCreateMutant:
    push 0723577A3h
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 022252282h
    call _WhisperMain

_NtCreatePagingFile:
    push 00E814C24h
    call _WhisperMain

_NtCreatePartition:
    push 0BEA7D03Bh
    call _WhisperMain

_NtCreatePort:
    push 0AFBDD24Dh
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 06CD612C5h
    call _WhisperMain

_NtCreateProcess:
    push 0379C3806h
    call _WhisperMain

_NtCreateProfile:
    push 0C89BC821h
    call _WhisperMain

_NtCreateProfileEx:
    push 002BBC5E5h
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 052CC7019h
    call _WhisperMain

_NtCreateResourceManager:
    push 04D97553Ah
    call _WhisperMain

_NtCreateSemaphore:
    push 09B0AEFE3h
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 00E987251h
    call _WhisperMain

_NtCreateThreadEx:
    push 092BEDC68h
    call _WhisperMain

_NtCreateTimer:
    push 01F9BEA10h
    call _WhisperMain

_NtCreateTimer2:
    push 00F84835Ah
    call _WhisperMain

_NtCreateToken:
    push 00F99E602h
    call _WhisperMain

_NtCreateTokenEx:
    push 06784BBC0h
    call _WhisperMain

_NtCreateTransaction:
    push 03ACADB59h
    call _WhisperMain

_NtCreateTransactionManager:
    push 0042E3CA4h
    call _WhisperMain

_NtCreateUserProcess:
    push 0872D9F40h
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0BC9A96C4h
    call _WhisperMain

_NtCreateWaitablePort:
    push 024F8AEE6h
    call _WhisperMain

_NtCreateWnfStateName:
    push 0B7109850h
    call _WhisperMain

_NtCreateWorkerFactory:
    push 001561FD0h
    call _WhisperMain

_NtDebugActiveProcess:
    push 0E343C0EDh
    call _WhisperMain

_NtDebugContinue:
    push 07D074CB4h
    call _WhisperMain

_NtDeleteAtom:
    push 035BBD4A9h
    call _WhisperMain

_NtDeleteBootEntry:
    push 00195F4EBh
    call _WhisperMain

_NtDeleteDriverEntry:
    push 019966F68h
    call _WhisperMain

_NtDeleteFile:
    push 03D3C2A80h
    call _WhisperMain

_NtDeleteKey:
    push 0665B11A0h
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 012B41E2Ah
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 02D0D36ADh
    call _WhisperMain

_NtDeleteValueKey:
    push 03A2F1598h
    call _WhisperMain

_NtDeleteWnfStateData:
    push 08E877890h
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0746AEB51h
    call _WhisperMain

_NtDisableLastKnownGood:
    push 02FB8B58Eh
    call _WhisperMain

_NtDisplayString:
    push 00C90C0C5h
    call _WhisperMain

_NtDrawText:
    push 0F74EC0E5h
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0F82EEE87h
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0E45CC1C3h
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 03C8C4D6Fh
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0B34A85F7h
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 084A867D4h
    call _WhisperMain

_NtExtendSection:
    push 000CB3E67h
    call _WhisperMain

_NtFilterBootOption:
    push 09405F6D9h
    call _WhisperMain

_NtFilterToken:
    push 003117798h
    call _WhisperMain

_NtFilterTokenEx:
    push 07489A8DCh
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0D6260C84h
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0FDCACE96h
    call _WhisperMain

_NtFlushInstructionCache:
    push 00D334E15h
    call _WhisperMain

_NtFlushKey:
    push 0152778D4h
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 002D882C0h
    call _WhisperMain

_NtFlushVirtualMemory:
    push 04390356Fh
    call _WhisperMain

_NtFlushWriteBuffer:
    push 003BF6B65h
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0F74DD4F2h
    call _WhisperMain

_NtFreezeRegistry:
    push 0F0AD35E0h
    call _WhisperMain

_NtFreezeTransactions:
    push 00792D5D5h
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0BEFAB868h
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 04E864A1Fh
    call _WhisperMain

_NtGetContextThread:
    push 018B0420Dh
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0143368D9h
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 066EAA155h
    call _WhisperMain

_NtGetDevicePowerState:
    push 0623D946Ch
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 086059C8Fh
    call _WhisperMain

_NtGetNextProcess:
    push 041DB4254h
    call _WhisperMain

_NtGetNextThread:
    push 01409DF26h
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0A312280Ah
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 039012389h
    call _WhisperMain

_NtGetWriteWatch:
    push 01E232287h
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 003961D26h
    call _WhisperMain

_NtImpersonateThread:
    push 093379F9Eh
    call _WhisperMain

_NtInitializeEnclave:
    push 08F38AF73h
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0E4413D0Eh
    call _WhisperMain

_NtInitializeRegistry:
    push 0DD4D283Eh
    call _WhisperMain

_NtInitiatePowerAction:
    push 0FA4C3A1Fh
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 03C087126h
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0605C2171h
    call _WhisperMain

_NtListenPort:
    push 060B36F30h
    call _WhisperMain

_NtLoadDriver:
    push 0F15E28F5h
    call _WhisperMain

_NtLoadEnclaveData:
    push 02281B4B4h
    call _WhisperMain

_NtLoadHotPatch:
    push 0928019A3h
    call _WhisperMain

_NtLoadKey:
    push 06ED28DA9h
    call _WhisperMain

_NtLoadKey2:
    push 0C7BC115Ch
    call _WhisperMain

_NtLoadKeyEx:
    push 0157AC126h
    call _WhisperMain

_NtLockFile:
    push 02883E127h
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0AE34A5A1h
    call _WhisperMain

_NtLockRegistryKey:
    push 02726C23Ah
    call _WhisperMain

_NtLockVirtualMemory:
    push 0C44CCECCh
    call _WhisperMain

_NtMakePermanentObject:
    push 074AF7433h
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0FAA301CCh
    call _WhisperMain

_NtManagePartition:
    push 03A8C5A5Bh
    call _WhisperMain

_NtMapCMFModule:
    push 0B4DC9E4Bh
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 08DBEBE3Ah
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 058D31614h
    call _WhisperMain

_NtModifyBootEntry:
    push 067F44350h
    call _WhisperMain

_NtModifyDriverEntry:
    push 00998273Eh
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 00C343AACh
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0AA98F44Fh
    call _WhisperMain

_NtNotifyChangeKey:
    push 069F1524Ch
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 026BA2B39h
    call _WhisperMain

_NtNotifyChangeSession:
    push 0438B2358h
    call _WhisperMain

_NtOpenEnlistment:
    push 0311170FBh
    call _WhisperMain

_NtOpenEventPair:
    push 08632625Fh
    call _WhisperMain

_NtOpenIoCompletion:
    push 0B52055B2h
    call _WhisperMain

_NtOpenJobObject:
    push 006BA2C07h
    call _WhisperMain

_NtOpenKeyEx:
    push 0ADA6E373h
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0C369F3B5h
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0C2DCF462h
    call _WhisperMain

_NtOpenKeyedEvent:
    push 038BA00FEh
    call _WhisperMain

_NtOpenMutant:
    push 02E80491Ah
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 02EAB0A7Ch
    call _WhisperMain

_NtOpenPartition:
    push 036AED5BBh
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 006B62935h
    call _WhisperMain

_NtOpenProcessToken:
    push 00997010Eh
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0009A020Bh
    call _WhisperMain

_NtOpenResourceManager:
    push 0F1B1DF6Dh
    call _WhisperMain

_NtOpenSemaphore:
    push 04B5A1264h
    call _WhisperMain

_NtOpenSession:
    push 00F940F06h
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 03886063Bh
    call _WhisperMain

_NtOpenThread:
    push 0785C7AF5h
    call _WhisperMain

_NtOpenTimer:
    push 03590371Ch
    call _WhisperMain

_NtOpenTransaction:
    push 0B2AC51FCh
    call _WhisperMain

_NtOpenTransactionManager:
    push 009B3715Eh
    call _WhisperMain

_NtPlugPlayControl:
    push 0F066DCA6h
    call _WhisperMain

_NtPrePrepareComplete:
    push 048B5A6E6h
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 039A5382Fh
    call _WhisperMain

_NtPrepareComplete:
    push 0B531A4BDh
    call _WhisperMain

_NtPrepareEnlistment:
    push 08AB5AF03h
    call _WhisperMain

_NtPrivilegeCheck:
    push 0CA55E3C9h
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0DC52D2CAh
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0DAA5F27Ah
    call _WhisperMain

_NtPropagationComplete:
    push 03EA5D729h
    call _WhisperMain

_NtPropagationFailed:
    push 0CA98D225h
    call _WhisperMain

_NtPulseEvent:
    push 01B0A7C90h
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 099BD9C3Eh
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0A01C7936h
    call _WhisperMain

_NtQueryBootOptions:
    push 04FDB7741h
    call _WhisperMain

_NtQueryDebugFilterState:
    push 09E01F88Ch
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 08AB84DE6h
    call _WhisperMain

_NtQueryDirectoryObject:
    push 06CBC6621h
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0633CBA97h
    call _WhisperMain

_NtQueryEaFile:
    push 035637BC6h
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0D841C6E4h
    call _WhisperMain

_NtQueryInformationAtom:
    push 075256BA4h
    call _WhisperMain

_NtQueryInformationByName:
    push 03AA210E5h
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 01B9AFFF1h
    call _WhisperMain

_NtQueryInformationJobObject:
    push 03AA43409h
    call _WhisperMain

_NtQueryInformationPort:
    push 07CB61924h
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 002B3F7D0h
    call _WhisperMain

_NtQueryInformationTransaction:
    push 006CE261Dh
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 00C36C46Ch
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 00E9AF7DBh
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0FB4CE0F0h
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0291E23B8h
    call _WhisperMain

_NtQueryIoCompletion:
    push 0248FA49Dh
    call _WhisperMain

_NtQueryLicenseValue:
    push 040DB0F10h
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 08185A23Fh
    call _WhisperMain

_NtQueryMutant:
    push 02EFA6F2Eh
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0B1D4A4B2h
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 09765CBB0h
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 061BD09A0h
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0E677AC50h
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 07DD7A47Ch
    call _WhisperMain

_NtQuerySecurityObject:
    push 005BD4F62h
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 096A1ABE5h
    call _WhisperMain

_NtQuerySemaphore:
    push 0C511B7B7h
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 01405FC79h
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 01632F53Ah
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0E3083E5Dh
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 09092C44Eh
    call _WhisperMain

_NtQueryTimerResolution:
    push 048D02E05h
    call _WhisperMain

_NtQueryWnfStateData:
    push 05B1DA140h
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 00E982C0Dh
    call _WhisperMain

_NtQueueApcThreadEx:
    push 08AAAAC15h
    call _WhisperMain

_NtRaiseException:
    push 01C3CF56Ch
    call _WhisperMain

_NtRaiseHardError:
    push 001F10563h
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 03867CA21h
    call _WhisperMain

_NtRecoverEnlistment:
    push 061D89ABFh
    call _WhisperMain

_NtRecoverResourceManager:
    push 03FA95770h
    call _WhisperMain

_NtRecoverTransactionManager:
    push 013228123h
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0654DE663h
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 05CB05938h
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 08921AEB3h
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0F851EEF5h
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 05AD26767h
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0463B0BF0h
    call _WhisperMain

_NtRenameKey:
    push 097CCA460h
    call _WhisperMain

_NtRenameTransactionManager:
    push 03E262CA6h
    call _WhisperMain

_NtReplaceKey:
    push 089D2BE63h
    call _WhisperMain

_NtReplacePartitionUnit:
    push 016AB3E30h
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0A435ABAEh
    call _WhisperMain

_NtRequestPort:
    push 022B258BCh
    call _WhisperMain

_NtResetEvent:
    push 08ED58946h
    call _WhisperMain

_NtResetWriteWatch:
    push 03CA8464Ah
    call _WhisperMain

_NtRestoreKey:
    push 07BBE9BD5h
    call _WhisperMain

_NtResumeProcess:
    push 04FA5483Eh
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 00E90CCC3h
    call _WhisperMain

_NtRollbackComplete:
    push 02F540BD4h
    call _WhisperMain

_NtRollbackEnlistment:
    push 0B7ABB221h
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0C8922E02h
    call _WhisperMain

_NtRollbackTransaction:
    push 0004BC61Bh
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0AE329C8Fh
    call _WhisperMain

_NtSaveKey:
    push 0AB989C26h
    call _WhisperMain

_NtSaveKeyEx:
    push 0B5B9FD78h
    call _WhisperMain

_NtSaveMergedKeys:
    push 0EE55F9DFh
    call _WhisperMain

_NtSecureConnectPort:
    push 0E90CE293h
    call _WhisperMain

_NtSerializeBoot:
    push 070206AAFh
    call _WhisperMain

_NtSetBootEntryOrder:
    push 03F5CAD71h
    call _WhisperMain

_NtSetBootOptions:
    push 09D89D750h
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 00AC0285Eh
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 054CADE0Eh
    call _WhisperMain

_NtSetContextThread:
    push 008A87A01h
    call _WhisperMain

_NtSetDebugFilterState:
    push 03E1DEF21h
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 05CCE5960h
    call _WhisperMain

_NtSetDefaultLocale:
    push 0519A6FCBh
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0189A0A27h
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 007A83CE5h
    call _WhisperMain

_NtSetEaFile:
    push 0A2FA64A6h
    call _WhisperMain

_NtSetHighEventPair:
    push 024B00C05h
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 023B13A26h
    call _WhisperMain

_NtSetIRTimer:
    push 021A23322h
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0EE33E6AFh
    call _WhisperMain

_NtSetInformationEnlistment:
    push 007A81C3Fh
    call _WhisperMain

_NtSetInformationJobObject:
    push 014B80615h
    call _WhisperMain

_NtSetInformationKey:
    push 03CD83F43h
    call _WhisperMain

_NtSetInformationResourceManager:
    push 095A364A7h
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0D847D6D6h
    call _WhisperMain

_NtSetInformationToken:
    push 01E50914Eh
    call _WhisperMain

_NtSetInformationTransaction:
    push 0C996C938h
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 04FD34148h
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 03BAB373Fh
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 088179E7Ah
    call _WhisperMain

_NtSetIntervalProfile:
    push 02DB9D43Dh
    call _WhisperMain

_NtSetIoCompletion:
    push 09AD0BA05h
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0D6D4048Eh
    call _WhisperMain

_NtSetLdtEntries:
    push 0EC8E3621h
    call _WhisperMain

_NtSetLowEventPair:
    push 082D18A4Ah
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 010B43029h
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 08536CBE3h
    call _WhisperMain

_NtSetSecurityObject:
    push 00D1F6986h
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0B8DE9D5Eh
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0BF81FD54h
    call _WhisperMain

_NtSetSystemInformation:
    push 02441D522h
    call _WhisperMain

_NtSetSystemPowerState:
    push 0708386CAh
    call _WhisperMain

_NtSetSystemTime:
    push 0B435FFE3h
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0EE4DC8C4h
    call _WhisperMain

_NtSetTimer2:
    push 057D4F08Dh
    call _WhisperMain

_NtSetTimerEx:
    push 00E84D426h
    call _WhisperMain

_NtSetTimerResolution:
    push 00E902FDFh
    call _WhisperMain

_NtSetUuidSeed:
    push 04862C14Fh
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0B238260Eh
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 09012F98Eh
    call _WhisperMain

_NtShutdownSystem:
    push 00E5DD1EDh
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 04494762Ch
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0253F2DA2h
    call _WhisperMain

_NtSinglePhaseReject:
    push 016BD2E11h
    call _WhisperMain

_NtStartProfile:
    push 0EFB9C72Ch
    call _WhisperMain

_NtStopProfile:
    push 0CB9B003Dh
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 082C35F7Bh
    call _WhisperMain

_NtSuspendProcess:
    push 01DA1042Ch
    call _WhisperMain

_NtSuspendThread:
    push 02C9F220Dh
    call _WhisperMain

_NtSystemDebugControl:
    push 0876885FDh
    call _WhisperMain

_NtTerminateEnclave:
    push 0BA2998A0h
    call _WhisperMain

_NtTerminateJobObject:
    push 020780925h
    call _WhisperMain

_NtTestAlert:
    push 08C27A582h
    call _WhisperMain

_NtThawRegistry:
    push 01083180Dh
    call _WhisperMain

_NtThawTransactions:
    push 03BEF7F25h
    call _WhisperMain

_NtTraceControl:
    push 0DC8ED816h
    call _WhisperMain

_NtTranslateFilePath:
    push 08798B016h
    call _WhisperMain

_NtUmsThreadYield:
    push 0E7B8EC1Eh
    call _WhisperMain

_NtUnloadDriver:
    push 0EAC7F36Ch
    call _WhisperMain

_NtUnloadKey:
    push 01DCDFFB6h
    call _WhisperMain

_NtUnloadKey2:
    push 0ABD0440Dh
    call _WhisperMain

_NtUnloadKeyEx:
    push 0F4783506h
    call _WhisperMain

_NtUnlockFile:
    push 0A13C9DBDh
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 073E2677Dh
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0D28901D3h
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 036A710FAh
    call _WhisperMain

_NtUpdateWnfStateData:
    push 062BD8CF0h
    call _WhisperMain

_NtVdmControl:
    push 0DD8CF356h
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 08C505AEAh
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0715A42FCh
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 048CB4B5Ch
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0E28E1BFFh
    call _WhisperMain

_NtWaitHighEventPair:
    push 010983409h
    call _WhisperMain

_NtWaitLowEventPair:
    push 02F01AD16h
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 02893B1BAh
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 08D13A98Ch
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0C51B81C8h
    call _WhisperMain

_NtClearSavepointTransaction:
    push 08873BAD7h
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 01AB33C23h
    call _WhisperMain

_NtSavepointTransaction:
    push 0E670989Dh
    call _WhisperMain

_NtSavepointComplete:
    push 004C92202h
    call _WhisperMain

_NtCreateSectionEx:
    push 00096F5EBh
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 03EBB5968h
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 010C83D68h
    call _WhisperMain

_NtListTransactions:
    push 05BC73D13h
    call _WhisperMain

_NtMarshallTransaction:
    push 0014A2217h
    call _WhisperMain

_NtPullTransaction:
    push 0F7AFD1E7h
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 07AAD7A3Ah
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 039A9FAFFh
    call _WhisperMain

_NtStartTm:
    push 021AC7B02h
    call _WhisperMain

_NtSetInformationProcess:
    push 08A2A95BBh
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 09B389FACh
    call _WhisperMain

_NtRequestWakeupLatency:
    push 002B66946h
    call _WhisperMain

_NtQuerySystemTime:
    push 0B52F9EBEh
    call _WhisperMain

_NtManageHotPatch:
    push 07E423460h
    call _WhisperMain

_NtContinueEx:
    push 0138F4354h
    call _WhisperMain

