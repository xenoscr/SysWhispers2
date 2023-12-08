[SECTION .data]
currentHash:    dd  0
returnAddress:  dq  0
syscallNumber:  dd  0
syscallAddress: dq  0

[SECTION .text]

BITS 64
DEFAULT REL

global NtAccessCheck
global NtWorkerFactoryWorkerReady
global NtAcceptConnectPort
global NtMapUserPhysicalPagesScatter
global NtWaitForSingleObject
global NtCallbackReturn
global NtReadFile
global NtDeviceIoControlFile
global NtWriteFile
global NtRemoveIoCompletion
global NtReleaseSemaphore
global NtReplyWaitReceivePort
global NtReplyPort
global NtSetInformationThread
global NtSetEvent
global NtClose
global NtQueryObject
global NtQueryInformationFile
global NtOpenKey
global NtEnumerateValueKey
global NtFindAtom
global NtQueryDefaultLocale
global NtQueryKey
global NtQueryValueKey
global NtAllocateVirtualMemory
global NtQueryInformationProcess
global NtWaitForMultipleObjects32
global NtWriteFileGather
global NtCreateKey
global NtFreeVirtualMemory
global NtImpersonateClientOfPort
global NtReleaseMutant
global NtQueryInformationToken
global NtRequestWaitReplyPort
global NtQueryVirtualMemory
global NtOpenThreadToken
global NtQueryInformationThread
global NtOpenProcess
global NtSetInformationFile
global NtMapViewOfSection
global NtAccessCheckAndAuditAlarm
global NtUnmapViewOfSection
global NtReplyWaitReceivePortEx
global NtTerminateProcess
global NtSetEventBoostPriority
global NtReadFileScatter
global NtOpenThreadTokenEx
global NtOpenProcessTokenEx
global NtQueryPerformanceCounter
global NtEnumerateKey
global NtOpenFile
global NtDelayExecution
global NtQueryDirectoryFile
global NtQuerySystemInformation
global NtOpenSection
global NtQueryTimer
global NtFsControlFile
global NtWriteVirtualMemory
global NtCloseObjectAuditAlarm
global NtDuplicateObject
global NtQueryAttributesFile
global NtClearEvent
global NtReadVirtualMemory
global NtOpenEvent
global NtAdjustPrivilegesToken
global NtDuplicateToken
global NtContinue
global NtQueryDefaultUILanguage
global NtQueueApcThread
global NtYieldExecution
global NtAddAtom
global NtCreateEvent
global NtQueryVolumeInformationFile
global NtCreateSection
global NtFlushBuffersFile
global NtApphelpCacheControl
global NtCreateProcessEx
global NtCreateThread
global NtIsProcessInJob
global NtProtectVirtualMemory
global NtQuerySection
global NtResumeThread
global NtTerminateThread
global NtReadRequestData
global NtCreateFile
global NtQueryEvent
global NtWriteRequestData
global NtOpenDirectoryObject
global NtAccessCheckByTypeAndAuditAlarm
global NtWaitForMultipleObjects
global NtSetInformationObject
global NtCancelIoFile
global NtTraceEvent
global NtPowerInformation
global NtSetValueKey
global NtCancelTimer
global NtSetTimer
global NtAccessCheckByType
global NtAccessCheckByTypeResultList
global NtAccessCheckByTypeResultListAndAuditAlarm
global NtAccessCheckByTypeResultListAndAuditAlarmByHandle
global NtAcquireProcessActivityReference
global NtAddAtomEx
global NtAddBootEntry
global NtAddDriverEntry
global NtAdjustGroupsToken
global NtAdjustTokenClaimsAndDeviceGroups
global NtAlertResumeThread
global NtAlertThread
global NtAlertThreadByThreadId
global NtAllocateLocallyUniqueId
global NtAllocateReserveObject
global NtAllocateUserPhysicalPages
global NtAllocateUuids
global NtAllocateVirtualMemoryEx
global NtAlpcAcceptConnectPort
global NtAlpcCancelMessage
global NtAlpcConnectPort
global NtAlpcConnectPortEx
global NtAlpcCreatePort
global NtAlpcCreatePortSection
global NtAlpcCreateResourceReserve
global NtAlpcCreateSectionView
global NtAlpcCreateSecurityContext
global NtAlpcDeletePortSection
global NtAlpcDeleteResourceReserve
global NtAlpcDeleteSectionView
global NtAlpcDeleteSecurityContext
global NtAlpcDisconnectPort
global NtAlpcImpersonateClientContainerOfPort
global NtAlpcImpersonateClientOfPort
global NtAlpcOpenSenderProcess
global NtAlpcOpenSenderThread
global NtAlpcQueryInformation
global NtAlpcQueryInformationMessage
global NtAlpcRevokeSecurityContext
global NtAlpcSendWaitReceivePort
global NtAlpcSetInformation
global NtAreMappedFilesTheSame
global NtAssignProcessToJobObject
global NtAssociateWaitCompletionPacket
global NtCallEnclave
global NtCancelIoFileEx
global NtCancelSynchronousIoFile
global NtCancelTimer2
global NtCancelWaitCompletionPacket
global NtCommitComplete
global NtCommitEnlistment
global NtCommitRegistryTransaction
global NtCommitTransaction
global NtCompactKeys
global NtCompareObjects
global NtCompareSigningLevels
global NtCompareTokens
global NtCompleteConnectPort
global NtCompressKey
global NtConnectPort
global NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
global NtCreateDebugObject
global NtCreateDirectoryObject
global NtCreateDirectoryObjectEx
global NtCreateEnclave
global NtCreateEnlistment
global NtCreateEventPair
global NtCreateIRTimer
global NtCreateIoCompletion
global NtCreateJobObject
global NtCreateJobSet
global NtCreateKeyTransacted
global NtCreateKeyedEvent
global NtCreateLowBoxToken
global NtCreateMailslotFile
global NtCreateMutant
global NtCreateNamedPipeFile
global NtCreatePagingFile
global NtCreatePartition
global NtCreatePort
global NtCreatePrivateNamespace
global NtCreateProcess
global NtCreateProfile
global NtCreateProfileEx
global NtCreateRegistryTransaction
global NtCreateResourceManager
global NtCreateSemaphore
global NtCreateSymbolicLinkObject
global NtCreateThreadEx
global NtCreateTimer
global NtCreateTimer2
global NtCreateToken
global NtCreateTokenEx
global NtCreateTransaction
global NtCreateTransactionManager
global NtCreateUserProcess
global NtCreateWaitCompletionPacket
global NtCreateWaitablePort
global NtCreateWnfStateName
global NtCreateWorkerFactory
global NtDebugActiveProcess
global NtDebugContinue
global NtDeleteAtom
global NtDeleteBootEntry
global NtDeleteDriverEntry
global NtDeleteFile
global NtDeleteKey
global NtDeleteObjectAuditAlarm
global NtDeletePrivateNamespace
global NtDeleteValueKey
global NtDeleteWnfStateData
global NtDeleteWnfStateName
global NtDisableLastKnownGood
global NtDisplayString
global NtDrawText
global NtEnableLastKnownGood
global NtEnumerateBootEntries
global NtEnumerateDriverEntries
global NtEnumerateSystemEnvironmentValuesEx
global NtEnumerateTransactionObject
global NtExtendSection
global NtFilterBootOption
global NtFilterToken
global NtFilterTokenEx
global NtFlushBuffersFileEx
global NtFlushInstallUILanguage
global NtFlushInstructionCache
global NtFlushKey
global NtFlushProcessWriteBuffers
global NtFlushVirtualMemory
global NtFlushWriteBuffer
global NtFreeUserPhysicalPages
global NtFreezeRegistry
global NtFreezeTransactions
global NtGetCachedSigningLevel
global NtGetCompleteWnfStateSubscription
global NtGetContextThread
global NtGetCurrentProcessorNumber
global NtGetCurrentProcessorNumberEx
global NtGetDevicePowerState
global NtGetMUIRegistryInfo
global NtGetNextProcess
global NtGetNextThread
global NtGetNlsSectionPtr
global NtGetNotificationResourceManager
global NtGetWriteWatch
global NtImpersonateAnonymousToken
global NtImpersonateThread
global NtInitializeEnclave
global NtInitializeNlsFiles
global NtInitializeRegistry
global NtInitiatePowerAction
global NtIsSystemResumeAutomatic
global NtIsUILanguageComitted
global NtListenPort
global NtLoadDriver
global NtLoadEnclaveData
global NtLoadHotPatch
global NtLoadKey
global NtLoadKey2
global NtLoadKeyEx
global NtLockFile
global NtLockProductActivationKeys
global NtLockRegistryKey
global NtLockVirtualMemory
global NtMakePermanentObject
global NtMakeTemporaryObject
global NtManagePartition
global NtMapCMFModule
global NtMapUserPhysicalPages
global NtMapViewOfSectionEx
global NtModifyBootEntry
global NtModifyDriverEntry
global NtNotifyChangeDirectoryFile
global NtNotifyChangeDirectoryFileEx
global NtNotifyChangeKey
global NtNotifyChangeMultipleKeys
global NtNotifyChangeSession
global NtOpenEnlistment
global NtOpenEventPair
global NtOpenIoCompletion
global NtOpenJobObject
global NtOpenKeyEx
global NtOpenKeyTransacted
global NtOpenKeyTransactedEx
global NtOpenKeyedEvent
global NtOpenMutant
global NtOpenObjectAuditAlarm
global NtOpenPartition
global NtOpenPrivateNamespace
global NtOpenProcessToken
global NtOpenRegistryTransaction
global NtOpenResourceManager
global NtOpenSemaphore
global NtOpenSession
global NtOpenSymbolicLinkObject
global NtOpenThread
global NtOpenTimer
global NtOpenTransaction
global NtOpenTransactionManager
global NtPlugPlayControl
global NtPrePrepareComplete
global NtPrePrepareEnlistment
global NtPrepareComplete
global NtPrepareEnlistment
global NtPrivilegeCheck
global NtPrivilegeObjectAuditAlarm
global NtPrivilegedServiceAuditAlarm
global NtPropagationComplete
global NtPropagationFailed
global NtPulseEvent
global NtQueryAuxiliaryCounterFrequency
global NtQueryBootEntryOrder
global NtQueryBootOptions
global NtQueryDebugFilterState
global NtQueryDirectoryFileEx
global NtQueryDirectoryObject
global NtQueryDriverEntryOrder
global NtQueryEaFile
global NtQueryFullAttributesFile
global NtQueryInformationAtom
global NtQueryInformationByName
global NtQueryInformationEnlistment
global NtQueryInformationJobObject
global NtQueryInformationPort
global NtQueryInformationResourceManager
global NtQueryInformationTransaction
global NtQueryInformationTransactionManager
global NtQueryInformationWorkerFactory
global NtQueryInstallUILanguage
global NtQueryIntervalProfile
global NtQueryIoCompletion
global NtQueryLicenseValue
global NtQueryMultipleValueKey
global NtQueryMutant
global NtQueryOpenSubKeys
global NtQueryOpenSubKeysEx
global NtQueryPortInformationProcess
global NtQueryQuotaInformationFile
global NtQuerySecurityAttributesToken
global NtQuerySecurityObject
global NtQuerySecurityPolicy
global NtQuerySemaphore
global NtQuerySymbolicLinkObject
global NtQuerySystemEnvironmentValue
global NtQuerySystemEnvironmentValueEx
global NtQuerySystemInformationEx
global NtQueryTimerResolution
global NtQueryWnfStateData
global NtQueryWnfStateNameInformation
global NtQueueApcThreadEx
global NtRaiseException
global NtRaiseHardError
global NtReadOnlyEnlistment
global NtRecoverEnlistment
global NtRecoverResourceManager
global NtRecoverTransactionManager
global NtRegisterProtocolAddressInformation
global NtRegisterThreadTerminatePort
global NtReleaseKeyedEvent
global NtReleaseWorkerFactoryWorker
global NtRemoveIoCompletionEx
global NtRemoveProcessDebug
global NtRenameKey
global NtRenameTransactionManager
global NtReplaceKey
global NtReplacePartitionUnit
global NtReplyWaitReplyPort
global NtRequestPort
global NtResetEvent
global NtResetWriteWatch
global NtRestoreKey
global NtResumeProcess
global NtRevertContainerImpersonation
global NtRollbackComplete
global NtRollbackEnlistment
global NtRollbackRegistryTransaction
global NtRollbackTransaction
global NtRollforwardTransactionManager
global NtSaveKey
global NtSaveKeyEx
global NtSaveMergedKeys
global NtSecureConnectPort
global NtSerializeBoot
global NtSetBootEntryOrder
global NtSetBootOptions
global NtSetCachedSigningLevel
global NtSetCachedSigningLevel2
global NtSetContextThread
global NtSetDebugFilterState
global NtSetDefaultHardErrorPort
global NtSetDefaultLocale
global NtSetDefaultUILanguage
global NtSetDriverEntryOrder
global NtSetEaFile
global NtSetHighEventPair
global NtSetHighWaitLowEventPair
global NtSetIRTimer
global NtSetInformationDebugObject
global NtSetInformationEnlistment
global NtSetInformationJobObject
global NtSetInformationKey
global NtSetInformationResourceManager
global NtSetInformationSymbolicLink
global NtSetInformationToken
global NtSetInformationTransaction
global NtSetInformationTransactionManager
global NtSetInformationVirtualMemory
global NtSetInformationWorkerFactory
global NtSetIntervalProfile
global NtSetIoCompletion
global NtSetIoCompletionEx
global NtSetLdtEntries
global NtSetLowEventPair
global NtSetLowWaitHighEventPair
global NtSetQuotaInformationFile
global NtSetSecurityObject
global NtSetSystemEnvironmentValue
global NtSetSystemEnvironmentValueEx
global NtSetSystemInformation
global NtSetSystemPowerState
global NtSetSystemTime
global NtSetThreadExecutionState
global NtSetTimer2
global NtSetTimerEx
global NtSetTimerResolution
global NtSetUuidSeed
global NtSetVolumeInformationFile
global NtSetWnfProcessNotificationEvent
global NtShutdownSystem
global NtShutdownWorkerFactory
global NtSignalAndWaitForSingleObject
global NtSinglePhaseReject
global NtStartProfile
global NtStopProfile
global NtSubscribeWnfStateChange
global NtSuspendProcess
global NtSuspendThread
global NtSystemDebugControl
global NtTerminateEnclave
global NtTerminateJobObject
global NtTestAlert
global NtThawRegistry
global NtThawTransactions
global NtTraceControl
global NtTranslateFilePath
global NtUmsThreadYield
global NtUnloadDriver
global NtUnloadKey
global NtUnloadKey2
global NtUnloadKeyEx
global NtUnlockFile
global NtUnlockVirtualMemory
global NtUnmapViewOfSectionEx
global NtUnsubscribeWnfStateChange
global NtUpdateWnfStateData
global NtVdmControl
global NtWaitForAlertByThreadId
global NtWaitForDebugEvent
global NtWaitForKeyedEvent
global NtWaitForWorkViaWorkerFactory
global NtWaitHighEventPair
global NtWaitLowEventPair
global NtAcquireCMFViewOwnership
global NtCancelDeviceWakeupRequest
global NtClearAllSavepointsTransaction
global NtClearSavepointTransaction
global NtRollbackSavepointTransaction
global NtSavepointTransaction
global NtSavepointComplete
global NtCreateSectionEx
global NtCreateCrossVmEvent
global NtGetPlugPlayEvent
global NtListTransactions
global NtMarshallTransaction
global NtPullTransaction
global NtReleaseCMFViewOwnership
global NtWaitForWnfNotifications
global NtStartTm
global NtSetInformationProcess
global NtRequestDeviceWakeup
global NtRequestWakeupLatency
global NtQuerySystemTime
global NtManageHotPatch
global NtContinueEx

global WhisperMain
extern SW2_GetSyscallNumber
extern SW2_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                   ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    mov dword [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress    ; Get a random syscall address
    mov qword [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, dword [syscallNumber]      ; Restore the syscall value
    add rsp, 28h
    mov rcx, [rsp+ 8]                   ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword [returnAddress]           ; Save the original return address
    call qword [syscallAddress]         ; Issue syscall
    push qword [returnAddress]          ; Restore the original return address
    ret

NtAccessCheck:
    mov dword [currentHash], 02C9E332Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWorkerFactoryWorkerReady:
    mov dword [currentHash], 003A27F57h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcceptConnectPort:
    mov dword [currentHash], 02AB5391Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPagesScatter:
    mov dword [currentHash], 08E649A02h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForSingleObject:
    mov dword [currentHash], 0F559E2DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallbackReturn:
    mov dword [currentHash], 06CF64F62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFile:
    mov dword [currentHash], 066B86A12h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeviceIoControlFile:
    mov dword [currentHash], 025BCAE9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFile:
    mov dword [currentHash], 0CCFB8428h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletion:
    mov dword [currentHash], 01F027FD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseSemaphore:
    mov dword [currentHash], 0F4181198h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePort:
    mov dword [currentHash], 020B20926h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyPort:
    mov dword [currentHash], 06EF06368h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationThread:
    mov dword [currentHash], 06B5473F7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEvent:
    mov dword [currentHash], 07EE44768h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClose:
    mov dword [currentHash], 094944D26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryObject:
    mov dword [currentHash], 09CBC67D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationFile:
    mov dword [currentHash], 078DE6158h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKey:
    mov dword [currentHash], 08ADEA579h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateValueKey:
    mov dword [currentHash], 01E1A0189h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFindAtom:
    mov dword [currentHash], 0D646D7D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultLocale:
    mov dword [currentHash], 001204DF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryKey:
    mov dword [currentHash], 059ED7852h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryValueKey:
    mov dword [currentHash], 01930F45Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemory:
    mov dword [currentHash], 00F812137h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationProcess:
    mov dword [currentHash], 0812484ACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects32:
    mov dword [currentHash], 07CEE7C39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFileGather:
    mov dword [currentHash], 05FCE7517h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKey:
    mov dword [currentHash], 04A0365A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeVirtualMemory:
    mov dword [currentHash], 03B952177h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateClientOfPort:
    mov dword [currentHash], 034B93726h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseMutant:
    mov dword [currentHash], 0BA0387A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationToken:
    mov dword [currentHash], 013A881ACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWaitReplyPort:
    mov dword [currentHash], 0DAB42FD5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVirtualMemory:
    mov dword [currentHash], 01F930501h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadToken:
    mov dword [currentHash], 079D2734Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationThread:
    mov dword [currentHash], 01C0BD6BDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcess:
    mov dword [currentHash], 0412944B0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationFile:
    mov dword [currentHash], 023244E22h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSection:
    mov dword [currentHash], 0D64FF69Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckAndAuditAlarm:
    mov dword [currentHash], 019BF1321h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSection:
    mov dword [currentHash], 03AD21C5Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePortEx:
    mov dword [currentHash], 0BB95EF49h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateProcess:
    mov dword [currentHash], 0C1E25400h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEventBoostPriority:
    mov dword [currentHash], 0C49F3EF3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFileScatter:
    mov dword [currentHash], 017AC232Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadTokenEx:
    mov dword [currentHash], 0029BD4C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessTokenEx:
    mov dword [currentHash], 0989ADE24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPerformanceCounter:
    mov dword [currentHash], 0F9751426h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateKey:
    mov dword [currentHash], 04B3E6A96h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenFile:
    mov dword [currentHash], 0D691DC26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDelayExecution:
    mov dword [currentHash], 004961FE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFile:
    mov dword [currentHash], 060BA6202h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformation:
    mov dword [currentHash], 09C33BCA1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSection:
    mov dword [currentHash], 0F4EF17F2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimer:
    mov dword [currentHash], 0EA5AE4D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFsControlFile:
    mov dword [currentHash], 0303B2989h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 00595031Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCloseObjectAuditAlarm:
    mov dword [currentHash], 0923594A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateObject:
    mov dword [currentHash], 00EA6E68Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAttributesFile:
    mov dword [currentHash], 0E670E6EAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearEvent:
    mov dword [currentHash], 0A0B3A925h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadVirtualMemory:
    mov dword [currentHash], 00D961311h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEvent:
    mov dword [currentHash], 0D9732600h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustPrivilegesToken:
    mov dword [currentHash], 0A1A53085h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateToken:
    mov dword [currentHash], 005309710h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinue:
    mov dword [currentHash], 0BF16AA99h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultUILanguage:
    mov dword [currentHash], 09331CF0Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThread:
    mov dword [currentHash], 00830469Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtYieldExecution:
    mov dword [currentHash], 0FC4FBAFBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtom:
    mov dword [currentHash], 024760726h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEvent:
    mov dword [currentHash], 01A3C9C2Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVolumeInformationFile:
    mov dword [currentHash], 0A1274927h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSection:
    mov dword [currentHash], 0E30CE39Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFile:
    mov dword [currentHash], 02FBCF185h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtApphelpCacheControl:
    mov dword [currentHash], 00B5E7B8Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcessEx:
    mov dword [currentHash], 09F95D341h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThread:
    mov dword [currentHash], 0248F3E30h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsProcessInJob:
    mov dword [currentHash], 0D4ADDE06h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtProtectVirtualMemory:
    mov dword [currentHash], 041AC3D5Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySection:
    mov dword [currentHash], 00F4C03EFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeThread:
    mov dword [currentHash], 0E2806CA1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateThread:
    mov dword [currentHash], 00EAE5467h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadRequestData:
    mov dword [currentHash], 0A20A7A30h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateFile:
    mov dword [currentHash], 0ABBA21ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEvent:
    mov dword [currentHash], 01EDBF680h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteRequestData:
    mov dword [currentHash], 05C92A8C0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenDirectoryObject:
    mov dword [currentHash], 08897EA68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeAndAuditAlarm:
    mov dword [currentHash], 092345460h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects:
    mov dword [currentHash], 0339D4373h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationObject:
    mov dword [currentHash], 08AA679AAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFile:
    mov dword [currentHash], 05AC36C5Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceEvent:
    mov dword [currentHash], 0BE08A4AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPowerInformation:
    mov dword [currentHash], 08F126A00h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetValueKey:
    mov dword [currentHash], 00F9AE984h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer:
    mov dword [currentHash], 01BA78EA3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer:
    mov dword [currentHash], 043975514h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByType:
    mov dword [currentHash], 01CDA026Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultList:
    mov dword [currentHash], 0A33B2326h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword [currentHash], 014CA96D6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword [currentHash], 068353E06h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireProcessActivityReference:
    mov dword [currentHash], 052DF4F46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtomEx:
    mov dword [currentHash], 0AB50F7B5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddBootEntry:
    mov dword [currentHash], 009981900h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddDriverEntry:
    mov dword [currentHash], 011980110h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustGroupsToken:
    mov dword [currentHash], 005D1591Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustTokenClaimsAndDeviceGroups:
    mov dword [currentHash], 0871C8385h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertResumeThread:
    mov dword [currentHash], 015AF5106h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThread:
    mov dword [currentHash], 0102F9E05h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThreadByThreadId:
    mov dword [currentHash], 040B96E7Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateLocallyUniqueId:
    mov dword [currentHash], 093BB581Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateReserveObject:
    mov dword [currentHash], 0173561B7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUserPhysicalPages:
    mov dword [currentHash], 089A2A018h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUuids:
    mov dword [currentHash], 02DF55339h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemoryEx:
    mov dword [currentHash], 0A0B61C93h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcAcceptConnectPort:
    mov dword [currentHash], 0E572FAE1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCancelMessage:
    mov dword [currentHash], 03395420Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPort:
    mov dword [currentHash], 01E8D0700h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPortEx:
    mov dword [currentHash], 0118C5F4Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePort:
    mov dword [currentHash], 03EB22B3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePortSection:
    mov dword [currentHash], 004D90C43h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateResourceReserve:
    mov dword [currentHash], 040D2B05Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSectionView:
    mov dword [currentHash], 0AB358F6Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSecurityContext:
    mov dword [currentHash], 010AEE4E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeletePortSection:
    mov dword [currentHash], 0D841C6CDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteResourceReserve:
    mov dword [currentHash], 0F65AA863h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSectionView:
    mov dword [currentHash], 030903503h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSecurityContext:
    mov dword [currentHash], 016820512h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDisconnectPort:
    mov dword [currentHash], 0653163ABh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientContainerOfPort:
    mov dword [currentHash], 0AEA2D323h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientOfPort:
    mov dword [currentHash], 021B23C3Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderProcess:
    mov dword [currentHash], 0622253A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderThread:
    mov dword [currentHash], 0148FD1A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformation:
    mov dword [currentHash], 0089E2A13h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformationMessage:
    mov dword [currentHash], 0EDCDB872h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcRevokeSecurityContext:
    mov dword [currentHash], 07762820Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSendWaitReceivePort:
    mov dword [currentHash], 022B3012Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSetInformation:
    mov dword [currentHash], 04EDB684Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAreMappedFilesTheSame:
    mov dword [currentHash], 01DB34B8Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssignProcessToJobObject:
    mov dword [currentHash], 08A99FA65h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssociateWaitCompletionPacket:
    mov dword [currentHash], 09CB98A24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallEnclave:
    mov dword [currentHash], 0552A302Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFileEx:
    mov dword [currentHash], 0069CB4A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelSynchronousIoFile:
    mov dword [currentHash], 03B98BA82h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer2:
    mov dword [currentHash], 0B8BC74ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelWaitCompletionPacket:
    mov dword [currentHash], 0782278BEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitComplete:
    mov dword [currentHash], 038C00C6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitEnlistment:
    mov dword [currentHash], 0F044EDD6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitRegistryTransaction:
    mov dword [currentHash], 004932405h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitTransaction:
    mov dword [currentHash], 092D55F8Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompactKeys:
    mov dword [currentHash], 0FB80EC2Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareObjects:
    mov dword [currentHash], 09FD369BFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareSigningLevels:
    mov dword [currentHash], 014CA7C2Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareTokens:
    mov dword [currentHash], 04DD06B0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompleteConnectPort:
    mov dword [currentHash], 058F3BB9Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompressKey:
    mov dword [currentHash], 025DD2042h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConnectPort:
    mov dword [currentHash], 0E671FDDEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword [currentHash], 06DD6BE97h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDebugObject:
    mov dword [currentHash], 0943BA083h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObject:
    mov dword [currentHash], 07AD43439h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObjectEx:
    mov dword [currentHash], 04CEB143Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnclave:
    mov dword [currentHash], 09B39BE73h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnlistment:
    mov dword [currentHash], 0DE52E7E4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEventPair:
    mov dword [currentHash], 040934C0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIRTimer:
    mov dword [currentHash], 02491D0EBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIoCompletion:
    mov dword [currentHash], 03C9B1C15h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobObject:
    mov dword [currentHash], 00DB1E7AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobSet:
    mov dword [currentHash], 0B03EEA91h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyTransacted:
    mov dword [currentHash], 018C94276h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyedEvent:
    mov dword [currentHash], 030B41928h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateLowBoxToken:
    mov dword [currentHash], 0CF91C202h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMailslotFile:
    mov dword [currentHash], 04E91A0DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMutant:
    mov dword [currentHash], 0723577A3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateNamedPipeFile:
    mov dword [currentHash], 022252282h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePagingFile:
    mov dword [currentHash], 00E814C24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePartition:
    mov dword [currentHash], 0BEA7D03Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePort:
    mov dword [currentHash], 0AFBDD24Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePrivateNamespace:
    mov dword [currentHash], 06CD612C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcess:
    mov dword [currentHash], 0379C3806h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfile:
    mov dword [currentHash], 0C89BC821h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfileEx:
    mov dword [currentHash], 002BBC5E5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateRegistryTransaction:
    mov dword [currentHash], 052CC7019h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateResourceManager:
    mov dword [currentHash], 04D97553Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSemaphore:
    mov dword [currentHash], 09B0AEFE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSymbolicLinkObject:
    mov dword [currentHash], 00E987251h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 092BEDC68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer:
    mov dword [currentHash], 01F9BEA10h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer2:
    mov dword [currentHash], 00F84835Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateToken:
    mov dword [currentHash], 00F99E602h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTokenEx:
    mov dword [currentHash], 06784BBC0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransaction:
    mov dword [currentHash], 03ACADB59h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransactionManager:
    mov dword [currentHash], 0042E3CA4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateUserProcess:
    mov dword [currentHash], 0872D9F40h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitCompletionPacket:
    mov dword [currentHash], 0BC9A96C4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitablePort:
    mov dword [currentHash], 024F8AEE6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWnfStateName:
    mov dword [currentHash], 0B7109850h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWorkerFactory:
    mov dword [currentHash], 001561FD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugActiveProcess:
    mov dword [currentHash], 0E343C0EDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugContinue:
    mov dword [currentHash], 07D074CB4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteAtom:
    mov dword [currentHash], 035BBD4A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteBootEntry:
    mov dword [currentHash], 00195F4EBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteDriverEntry:
    mov dword [currentHash], 019966F68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteFile:
    mov dword [currentHash], 03D3C2A80h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteKey:
    mov dword [currentHash], 0665B11A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteObjectAuditAlarm:
    mov dword [currentHash], 012B41E2Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeletePrivateNamespace:
    mov dword [currentHash], 02D0D36ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteValueKey:
    mov dword [currentHash], 03A2F1598h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateData:
    mov dword [currentHash], 08E877890h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateName:
    mov dword [currentHash], 0746AEB51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisableLastKnownGood:
    mov dword [currentHash], 02FB8B58Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisplayString:
    mov dword [currentHash], 00C90C0C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDrawText:
    mov dword [currentHash], 0F74EC0E5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnableLastKnownGood:
    mov dword [currentHash], 0F82EEE87h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateBootEntries:
    mov dword [currentHash], 0E45CC1C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateDriverEntries:
    mov dword [currentHash], 03C8C4D6Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateSystemEnvironmentValuesEx:
    mov dword [currentHash], 0B34A85F7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateTransactionObject:
    mov dword [currentHash], 084A867D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtExtendSection:
    mov dword [currentHash], 000CB3E67h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterBootOption:
    mov dword [currentHash], 09405F6D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterToken:
    mov dword [currentHash], 003117798h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterTokenEx:
    mov dword [currentHash], 07489A8DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFileEx:
    mov dword [currentHash], 0D6260C84h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstallUILanguage:
    mov dword [currentHash], 0FDCACE96h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstructionCache:
    mov dword [currentHash], 00D334E15h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushKey:
    mov dword [currentHash], 0152778D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushProcessWriteBuffers:
    mov dword [currentHash], 002D882C0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushVirtualMemory:
    mov dword [currentHash], 04390356Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushWriteBuffer:
    mov dword [currentHash], 003BF6B65h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeUserPhysicalPages:
    mov dword [currentHash], 0F74DD4F2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeRegistry:
    mov dword [currentHash], 0F0AD35E0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeTransactions:
    mov dword [currentHash], 00792D5D5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCachedSigningLevel:
    mov dword [currentHash], 0BEFAB868h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCompleteWnfStateSubscription:
    mov dword [currentHash], 04E864A1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetContextThread:
    mov dword [currentHash], 018B0420Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumber:
    mov dword [currentHash], 0143368D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumberEx:
    mov dword [currentHash], 066EAA155h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetDevicePowerState:
    mov dword [currentHash], 0623D946Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetMUIRegistryInfo:
    mov dword [currentHash], 086059C8Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextProcess:
    mov dword [currentHash], 041DB4254h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextThread:
    mov dword [currentHash], 01409DF26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNlsSectionPtr:
    mov dword [currentHash], 0A312280Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNotificationResourceManager:
    mov dword [currentHash], 039012389h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetWriteWatch:
    mov dword [currentHash], 01E232287h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateAnonymousToken:
    mov dword [currentHash], 003961D26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateThread:
    mov dword [currentHash], 093379F9Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeEnclave:
    mov dword [currentHash], 08F38AF73h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeNlsFiles:
    mov dword [currentHash], 0E4413D0Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeRegistry:
    mov dword [currentHash], 0DD4D283Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitiatePowerAction:
    mov dword [currentHash], 0FA4C3A1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsSystemResumeAutomatic:
    mov dword [currentHash], 03C087126h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsUILanguageComitted:
    mov dword [currentHash], 0605C2171h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListenPort:
    mov dword [currentHash], 060B36F30h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadDriver:
    mov dword [currentHash], 0F15E28F5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadEnclaveData:
    mov dword [currentHash], 02281B4B4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadHotPatch:
    mov dword [currentHash], 0928019A3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey:
    mov dword [currentHash], 06ED28DA9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey2:
    mov dword [currentHash], 0C7BC115Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKeyEx:
    mov dword [currentHash], 0157AC126h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockFile:
    mov dword [currentHash], 02883E127h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockProductActivationKeys:
    mov dword [currentHash], 0AE34A5A1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockRegistryKey:
    mov dword [currentHash], 02726C23Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockVirtualMemory:
    mov dword [currentHash], 0C44CCECCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakePermanentObject:
    mov dword [currentHash], 074AF7433h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakeTemporaryObject:
    mov dword [currentHash], 0FAA301CCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManagePartition:
    mov dword [currentHash], 03A8C5A5Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapCMFModule:
    mov dword [currentHash], 0B4DC9E4Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPages:
    mov dword [currentHash], 08DBEBE3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSectionEx:
    mov dword [currentHash], 058D31614h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyBootEntry:
    mov dword [currentHash], 067F44350h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyDriverEntry:
    mov dword [currentHash], 00998273Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFile:
    mov dword [currentHash], 00C343AACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFileEx:
    mov dword [currentHash], 0AA98F44Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeKey:
    mov dword [currentHash], 069F1524Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeMultipleKeys:
    mov dword [currentHash], 026BA2B39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeSession:
    mov dword [currentHash], 0438B2358h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEnlistment:
    mov dword [currentHash], 0311170FBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEventPair:
    mov dword [currentHash], 08632625Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenIoCompletion:
    mov dword [currentHash], 0B52055B2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenJobObject:
    mov dword [currentHash], 006BA2C07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyEx:
    mov dword [currentHash], 0ADA6E373h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransacted:
    mov dword [currentHash], 0C369F3B5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransactedEx:
    mov dword [currentHash], 0C2DCF462h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyedEvent:
    mov dword [currentHash], 038BA00FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenMutant:
    mov dword [currentHash], 02E80491Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenObjectAuditAlarm:
    mov dword [currentHash], 02EAB0A7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPartition:
    mov dword [currentHash], 036AED5BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPrivateNamespace:
    mov dword [currentHash], 006B62935h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessToken:
    mov dword [currentHash], 00997010Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenRegistryTransaction:
    mov dword [currentHash], 0009A020Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenResourceManager:
    mov dword [currentHash], 0F1B1DF6Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSemaphore:
    mov dword [currentHash], 04B5A1264h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSession:
    mov dword [currentHash], 00F940F06h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSymbolicLinkObject:
    mov dword [currentHash], 03886063Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThread:
    mov dword [currentHash], 0785C7AF5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTimer:
    mov dword [currentHash], 03590371Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransaction:
    mov dword [currentHash], 0B2AC51FCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransactionManager:
    mov dword [currentHash], 009B3715Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPlugPlayControl:
    mov dword [currentHash], 0F066DCA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareComplete:
    mov dword [currentHash], 048B5A6E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareEnlistment:
    mov dword [currentHash], 039A5382Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareComplete:
    mov dword [currentHash], 0B531A4BDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareEnlistment:
    mov dword [currentHash], 08AB5AF03h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeCheck:
    mov dword [currentHash], 0CA55E3C9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeObjectAuditAlarm:
    mov dword [currentHash], 0DC52D2CAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegedServiceAuditAlarm:
    mov dword [currentHash], 0DAA5F27Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationComplete:
    mov dword [currentHash], 03EA5D729h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationFailed:
    mov dword [currentHash], 0CA98D225h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPulseEvent:
    mov dword [currentHash], 01B0A7C90h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAuxiliaryCounterFrequency:
    mov dword [currentHash], 099BD9C3Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootEntryOrder:
    mov dword [currentHash], 0A01C7936h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootOptions:
    mov dword [currentHash], 04FDB7741h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDebugFilterState:
    mov dword [currentHash], 09E01F88Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFileEx:
    mov dword [currentHash], 08AB84DE6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryObject:
    mov dword [currentHash], 06CBC6621h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDriverEntryOrder:
    mov dword [currentHash], 0633CBA97h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEaFile:
    mov dword [currentHash], 035637BC6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryFullAttributesFile:
    mov dword [currentHash], 0D841C6E4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationAtom:
    mov dword [currentHash], 075256BA4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationByName:
    mov dword [currentHash], 03AA210E5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationEnlistment:
    mov dword [currentHash], 01B9AFFF1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationJobObject:
    mov dword [currentHash], 03AA43409h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationPort:
    mov dword [currentHash], 07CB61924h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationResourceManager:
    mov dword [currentHash], 002B3F7D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransaction:
    mov dword [currentHash], 006CE261Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransactionManager:
    mov dword [currentHash], 00C36C46Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationWorkerFactory:
    mov dword [currentHash], 00E9AF7DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInstallUILanguage:
    mov dword [currentHash], 0FB4CE0F0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIntervalProfile:
    mov dword [currentHash], 0291E23B8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIoCompletion:
    mov dword [currentHash], 0248FA49Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryLicenseValue:
    mov dword [currentHash], 040DB0F10h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMultipleValueKey:
    mov dword [currentHash], 08185A23Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMutant:
    mov dword [currentHash], 02EFA6F2Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeys:
    mov dword [currentHash], 0B1D4A4B2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeysEx:
    mov dword [currentHash], 09765CBB0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPortInformationProcess:
    mov dword [currentHash], 061BD09A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryQuotaInformationFile:
    mov dword [currentHash], 0E677AC50h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityAttributesToken:
    mov dword [currentHash], 07DD7A47Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityObject:
    mov dword [currentHash], 005BD4F62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityPolicy:
    mov dword [currentHash], 096A1ABE5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySemaphore:
    mov dword [currentHash], 0C511B7B7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySymbolicLinkObject:
    mov dword [currentHash], 01405FC79h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValue:
    mov dword [currentHash], 01632F53Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValueEx:
    mov dword [currentHash], 0E3083E5Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformationEx:
    mov dword [currentHash], 09092C44Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimerResolution:
    mov dword [currentHash], 048D02E05h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateData:
    mov dword [currentHash], 05B1DA140h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateNameInformation:
    mov dword [currentHash], 00E982C0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThreadEx:
    mov dword [currentHash], 08AAAAC15h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseException:
    mov dword [currentHash], 01C3CF56Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseHardError:
    mov dword [currentHash], 001F10563h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadOnlyEnlistment:
    mov dword [currentHash], 03867CA21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverEnlistment:
    mov dword [currentHash], 061D89ABFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverResourceManager:
    mov dword [currentHash], 03FA95770h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverTransactionManager:
    mov dword [currentHash], 013228123h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterProtocolAddressInformation:
    mov dword [currentHash], 0654DE663h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterThreadTerminatePort:
    mov dword [currentHash], 05CB05938h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseKeyedEvent:
    mov dword [currentHash], 08921AEB3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseWorkerFactoryWorker:
    mov dword [currentHash], 0F851EEF5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletionEx:
    mov dword [currentHash], 05AD26767h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveProcessDebug:
    mov dword [currentHash], 0463B0BF0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameKey:
    mov dword [currentHash], 097CCA460h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameTransactionManager:
    mov dword [currentHash], 03E262CA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplaceKey:
    mov dword [currentHash], 089D2BE63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplacePartitionUnit:
    mov dword [currentHash], 016AB3E30h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReplyPort:
    mov dword [currentHash], 0A435ABAEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestPort:
    mov dword [currentHash], 022B258BCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetEvent:
    mov dword [currentHash], 08ED58946h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetWriteWatch:
    mov dword [currentHash], 03CA8464Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRestoreKey:
    mov dword [currentHash], 07BBE9BD5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeProcess:
    mov dword [currentHash], 04FA5483Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRevertContainerImpersonation:
    mov dword [currentHash], 00E90CCC3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackComplete:
    mov dword [currentHash], 02F540BD4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackEnlistment:
    mov dword [currentHash], 0B7ABB221h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackRegistryTransaction:
    mov dword [currentHash], 0C8922E02h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackTransaction:
    mov dword [currentHash], 0004BC61Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollforwardTransactionManager:
    mov dword [currentHash], 0AE329C8Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKey:
    mov dword [currentHash], 0AB989C26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKeyEx:
    mov dword [currentHash], 0B5B9FD78h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveMergedKeys:
    mov dword [currentHash], 0EE55F9DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSecureConnectPort:
    mov dword [currentHash], 0E90CE293h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSerializeBoot:
    mov dword [currentHash], 070206AAFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootEntryOrder:
    mov dword [currentHash], 03F5CAD71h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootOptions:
    mov dword [currentHash], 09D89D750h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel:
    mov dword [currentHash], 00AC0285Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel2:
    mov dword [currentHash], 054CADE0Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetContextThread:
    mov dword [currentHash], 008A87A01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDebugFilterState:
    mov dword [currentHash], 03E1DEF21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultHardErrorPort:
    mov dword [currentHash], 05CCE5960h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultLocale:
    mov dword [currentHash], 0519A6FCBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultUILanguage:
    mov dword [currentHash], 0189A0A27h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDriverEntryOrder:
    mov dword [currentHash], 007A83CE5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEaFile:
    mov dword [currentHash], 0A2FA64A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighEventPair:
    mov dword [currentHash], 024B00C05h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighWaitLowEventPair:
    mov dword [currentHash], 023B13A26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIRTimer:
    mov dword [currentHash], 021A23322h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationDebugObject:
    mov dword [currentHash], 0EE33E6AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationEnlistment:
    mov dword [currentHash], 007A81C3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationJobObject:
    mov dword [currentHash], 014B80615h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationKey:
    mov dword [currentHash], 03CD83F43h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationResourceManager:
    mov dword [currentHash], 095A364A7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationSymbolicLink:
    mov dword [currentHash], 0D847D6D6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationToken:
    mov dword [currentHash], 01E50914Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransaction:
    mov dword [currentHash], 0C996C938h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransactionManager:
    mov dword [currentHash], 04FD34148h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationVirtualMemory:
    mov dword [currentHash], 03BAB373Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationWorkerFactory:
    mov dword [currentHash], 088179E7Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIntervalProfile:
    mov dword [currentHash], 02DB9D43Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletion:
    mov dword [currentHash], 09AD0BA05h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletionEx:
    mov dword [currentHash], 0D6D4048Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLdtEntries:
    mov dword [currentHash], 0EC8E3621h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowEventPair:
    mov dword [currentHash], 082D18A4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowWaitHighEventPair:
    mov dword [currentHash], 010B43029h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetQuotaInformationFile:
    mov dword [currentHash], 08536CBE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSecurityObject:
    mov dword [currentHash], 00D1F6986h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValue:
    mov dword [currentHash], 0B8DE9D5Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValueEx:
    mov dword [currentHash], 0BF81FD54h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemInformation:
    mov dword [currentHash], 02441D522h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemPowerState:
    mov dword [currentHash], 0708386CAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemTime:
    mov dword [currentHash], 0B435FFE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetThreadExecutionState:
    mov dword [currentHash], 0EE4DC8C4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer2:
    mov dword [currentHash], 057D4F08Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerEx:
    mov dword [currentHash], 00E84D426h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerResolution:
    mov dword [currentHash], 00E902FDFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetUuidSeed:
    mov dword [currentHash], 04862C14Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetVolumeInformationFile:
    mov dword [currentHash], 0B238260Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetWnfProcessNotificationEvent:
    mov dword [currentHash], 09012F98Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownSystem:
    mov dword [currentHash], 00E5DD1EDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownWorkerFactory:
    mov dword [currentHash], 04494762Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSignalAndWaitForSingleObject:
    mov dword [currentHash], 0253F2DA2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSinglePhaseReject:
    mov dword [currentHash], 016BD2E11h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartProfile:
    mov dword [currentHash], 0EFB9C72Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStopProfile:
    mov dword [currentHash], 0CB9B003Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSubscribeWnfStateChange:
    mov dword [currentHash], 082C35F7Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendProcess:
    mov dword [currentHash], 01DA1042Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendThread:
    mov dword [currentHash], 02C9F220Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSystemDebugControl:
    mov dword [currentHash], 0876885FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateEnclave:
    mov dword [currentHash], 0BA2998A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateJobObject:
    mov dword [currentHash], 020780925h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTestAlert:
    mov dword [currentHash], 08C27A582h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawRegistry:
    mov dword [currentHash], 01083180Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawTransactions:
    mov dword [currentHash], 03BEF7F25h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceControl:
    mov dword [currentHash], 0DC8ED816h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTranslateFilePath:
    mov dword [currentHash], 08798B016h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUmsThreadYield:
    mov dword [currentHash], 0E7B8EC1Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadDriver:
    mov dword [currentHash], 0EAC7F36Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey:
    mov dword [currentHash], 01DCDFFB6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey2:
    mov dword [currentHash], 0ABD0440Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKeyEx:
    mov dword [currentHash], 0F4783506h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockFile:
    mov dword [currentHash], 0A13C9DBDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockVirtualMemory:
    mov dword [currentHash], 073E2677Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSectionEx:
    mov dword [currentHash], 0D28901D3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnsubscribeWnfStateChange:
    mov dword [currentHash], 036A710FAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUpdateWnfStateData:
    mov dword [currentHash], 062BD8CF0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtVdmControl:
    mov dword [currentHash], 0DD8CF356h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForAlertByThreadId:
    mov dword [currentHash], 08C505AEAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForDebugEvent:
    mov dword [currentHash], 0715A42FCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForKeyedEvent:
    mov dword [currentHash], 048CB4B5Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWorkViaWorkerFactory:
    mov dword [currentHash], 0E28E1BFFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitHighEventPair:
    mov dword [currentHash], 010983409h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitLowEventPair:
    mov dword [currentHash], 02F01AD16h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireCMFViewOwnership:
    mov dword [currentHash], 02893B1BAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelDeviceWakeupRequest:
    mov dword [currentHash], 08D13A98Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearAllSavepointsTransaction:
    mov dword [currentHash], 0C51B81C8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearSavepointTransaction:
    mov dword [currentHash], 08873BAD7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackSavepointTransaction:
    mov dword [currentHash], 01AB33C23h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointTransaction:
    mov dword [currentHash], 0E670989Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointComplete:
    mov dword [currentHash], 004C92202h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSectionEx:
    mov dword [currentHash], 00096F5EBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateCrossVmEvent:
    mov dword [currentHash], 03EBB5968h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetPlugPlayEvent:
    mov dword [currentHash], 010C83D68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListTransactions:
    mov dword [currentHash], 05BC73D13h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMarshallTransaction:
    mov dword [currentHash], 0014A2217h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPullTransaction:
    mov dword [currentHash], 0F7AFD1E7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseCMFViewOwnership:
    mov dword [currentHash], 07AAD7A3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWnfNotifications:
    mov dword [currentHash], 039A9FAFFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartTm:
    mov dword [currentHash], 021AC7B02h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationProcess:
    mov dword [currentHash], 08A2A95BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestDeviceWakeup:
    mov dword [currentHash], 09B389FACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWakeupLatency:
    mov dword [currentHash], 002B66946h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemTime:
    mov dword [currentHash], 0B52F9EBEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManageHotPatch:
    mov dword [currentHash], 07E423460h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinueEx:
    mov dword [currentHash], 0138F4354h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

