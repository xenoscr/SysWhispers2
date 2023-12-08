.intel_syntax noprefix
.data
currentHash:    .long   0

.text
.global NtAccessCheck
.global NtWorkerFactoryWorkerReady
.global NtAcceptConnectPort
.global NtMapUserPhysicalPagesScatter
.global NtWaitForSingleObject
.global NtCallbackReturn
.global NtReadFile
.global NtDeviceIoControlFile
.global NtWriteFile
.global NtRemoveIoCompletion
.global NtReleaseSemaphore
.global NtReplyWaitReceivePort
.global NtReplyPort
.global NtSetInformationThread
.global NtSetEvent
.global NtClose
.global NtQueryObject
.global NtQueryInformationFile
.global NtOpenKey
.global NtEnumerateValueKey
.global NtFindAtom
.global NtQueryDefaultLocale
.global NtQueryKey
.global NtQueryValueKey
.global NtAllocateVirtualMemory
.global NtQueryInformationProcess
.global NtWaitForMultipleObjects32
.global NtWriteFileGather
.global NtCreateKey
.global NtFreeVirtualMemory
.global NtImpersonateClientOfPort
.global NtReleaseMutant
.global NtQueryInformationToken
.global NtRequestWaitReplyPort
.global NtQueryVirtualMemory
.global NtOpenThreadToken
.global NtQueryInformationThread
.global NtOpenProcess
.global NtSetInformationFile
.global NtMapViewOfSection
.global NtAccessCheckAndAuditAlarm
.global NtUnmapViewOfSection
.global NtReplyWaitReceivePortEx
.global NtTerminateProcess
.global NtSetEventBoostPriority
.global NtReadFileScatter
.global NtOpenThreadTokenEx
.global NtOpenProcessTokenEx
.global NtQueryPerformanceCounter
.global NtEnumerateKey
.global NtOpenFile
.global NtDelayExecution
.global NtQueryDirectoryFile
.global NtQuerySystemInformation
.global NtOpenSection
.global NtQueryTimer
.global NtFsControlFile
.global NtWriteVirtualMemory
.global NtCloseObjectAuditAlarm
.global NtDuplicateObject
.global NtQueryAttributesFile
.global NtClearEvent
.global NtReadVirtualMemory
.global NtOpenEvent
.global NtAdjustPrivilegesToken
.global NtDuplicateToken
.global NtContinue
.global NtQueryDefaultUILanguage
.global NtQueueApcThread
.global NtYieldExecution
.global NtAddAtom
.global NtCreateEvent
.global NtQueryVolumeInformationFile
.global NtCreateSection
.global NtFlushBuffersFile
.global NtApphelpCacheControl
.global NtCreateProcessEx
.global NtCreateThread
.global NtIsProcessInJob
.global NtProtectVirtualMemory
.global NtQuerySection
.global NtResumeThread
.global NtTerminateThread
.global NtReadRequestData
.global NtCreateFile
.global NtQueryEvent
.global NtWriteRequestData
.global NtOpenDirectoryObject
.global NtAccessCheckByTypeAndAuditAlarm
.global NtWaitForMultipleObjects
.global NtSetInformationObject
.global NtCancelIoFile
.global NtTraceEvent
.global NtPowerInformation
.global NtSetValueKey
.global NtCancelTimer
.global NtSetTimer
.global NtAccessCheckByType
.global NtAccessCheckByTypeResultList
.global NtAccessCheckByTypeResultListAndAuditAlarm
.global NtAccessCheckByTypeResultListAndAuditAlarmByHandle
.global NtAcquireProcessActivityReference
.global NtAddAtomEx
.global NtAddBootEntry
.global NtAddDriverEntry
.global NtAdjustGroupsToken
.global NtAdjustTokenClaimsAndDeviceGroups
.global NtAlertResumeThread
.global NtAlertThread
.global NtAlertThreadByThreadId
.global NtAllocateLocallyUniqueId
.global NtAllocateReserveObject
.global NtAllocateUserPhysicalPages
.global NtAllocateUuids
.global NtAllocateVirtualMemoryEx
.global NtAlpcAcceptConnectPort
.global NtAlpcCancelMessage
.global NtAlpcConnectPort
.global NtAlpcConnectPortEx
.global NtAlpcCreatePort
.global NtAlpcCreatePortSection
.global NtAlpcCreateResourceReserve
.global NtAlpcCreateSectionView
.global NtAlpcCreateSecurityContext
.global NtAlpcDeletePortSection
.global NtAlpcDeleteResourceReserve
.global NtAlpcDeleteSectionView
.global NtAlpcDeleteSecurityContext
.global NtAlpcDisconnectPort
.global NtAlpcImpersonateClientContainerOfPort
.global NtAlpcImpersonateClientOfPort
.global NtAlpcOpenSenderProcess
.global NtAlpcOpenSenderThread
.global NtAlpcQueryInformation
.global NtAlpcQueryInformationMessage
.global NtAlpcRevokeSecurityContext
.global NtAlpcSendWaitReceivePort
.global NtAlpcSetInformation
.global NtAreMappedFilesTheSame
.global NtAssignProcessToJobObject
.global NtAssociateWaitCompletionPacket
.global NtCallEnclave
.global NtCancelIoFileEx
.global NtCancelSynchronousIoFile
.global NtCancelTimer2
.global NtCancelWaitCompletionPacket
.global NtCommitComplete
.global NtCommitEnlistment
.global NtCommitRegistryTransaction
.global NtCommitTransaction
.global NtCompactKeys
.global NtCompareObjects
.global NtCompareSigningLevels
.global NtCompareTokens
.global NtCompleteConnectPort
.global NtCompressKey
.global NtConnectPort
.global NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
.global NtCreateDebugObject
.global NtCreateDirectoryObject
.global NtCreateDirectoryObjectEx
.global NtCreateEnclave
.global NtCreateEnlistment
.global NtCreateEventPair
.global NtCreateIRTimer
.global NtCreateIoCompletion
.global NtCreateJobObject
.global NtCreateJobSet
.global NtCreateKeyTransacted
.global NtCreateKeyedEvent
.global NtCreateLowBoxToken
.global NtCreateMailslotFile
.global NtCreateMutant
.global NtCreateNamedPipeFile
.global NtCreatePagingFile
.global NtCreatePartition
.global NtCreatePort
.global NtCreatePrivateNamespace
.global NtCreateProcess
.global NtCreateProfile
.global NtCreateProfileEx
.global NtCreateRegistryTransaction
.global NtCreateResourceManager
.global NtCreateSemaphore
.global NtCreateSymbolicLinkObject
.global NtCreateThreadEx
.global NtCreateTimer
.global NtCreateTimer2
.global NtCreateToken
.global NtCreateTokenEx
.global NtCreateTransaction
.global NtCreateTransactionManager
.global NtCreateUserProcess
.global NtCreateWaitCompletionPacket
.global NtCreateWaitablePort
.global NtCreateWnfStateName
.global NtCreateWorkerFactory
.global NtDebugActiveProcess
.global NtDebugContinue
.global NtDeleteAtom
.global NtDeleteBootEntry
.global NtDeleteDriverEntry
.global NtDeleteFile
.global NtDeleteKey
.global NtDeleteObjectAuditAlarm
.global NtDeletePrivateNamespace
.global NtDeleteValueKey
.global NtDeleteWnfStateData
.global NtDeleteWnfStateName
.global NtDisableLastKnownGood
.global NtDisplayString
.global NtDrawText
.global NtEnableLastKnownGood
.global NtEnumerateBootEntries
.global NtEnumerateDriverEntries
.global NtEnumerateSystemEnvironmentValuesEx
.global NtEnumerateTransactionObject
.global NtExtendSection
.global NtFilterBootOption
.global NtFilterToken
.global NtFilterTokenEx
.global NtFlushBuffersFileEx
.global NtFlushInstallUILanguage
.global NtFlushInstructionCache
.global NtFlushKey
.global NtFlushProcessWriteBuffers
.global NtFlushVirtualMemory
.global NtFlushWriteBuffer
.global NtFreeUserPhysicalPages
.global NtFreezeRegistry
.global NtFreezeTransactions
.global NtGetCachedSigningLevel
.global NtGetCompleteWnfStateSubscription
.global NtGetContextThread
.global NtGetCurrentProcessorNumber
.global NtGetCurrentProcessorNumberEx
.global NtGetDevicePowerState
.global NtGetMUIRegistryInfo
.global NtGetNextProcess
.global NtGetNextThread
.global NtGetNlsSectionPtr
.global NtGetNotificationResourceManager
.global NtGetWriteWatch
.global NtImpersonateAnonymousToken
.global NtImpersonateThread
.global NtInitializeEnclave
.global NtInitializeNlsFiles
.global NtInitializeRegistry
.global NtInitiatePowerAction
.global NtIsSystemResumeAutomatic
.global NtIsUILanguageComitted
.global NtListenPort
.global NtLoadDriver
.global NtLoadEnclaveData
.global NtLoadHotPatch
.global NtLoadKey
.global NtLoadKey2
.global NtLoadKeyEx
.global NtLockFile
.global NtLockProductActivationKeys
.global NtLockRegistryKey
.global NtLockVirtualMemory
.global NtMakePermanentObject
.global NtMakeTemporaryObject
.global NtManagePartition
.global NtMapCMFModule
.global NtMapUserPhysicalPages
.global NtMapViewOfSectionEx
.global NtModifyBootEntry
.global NtModifyDriverEntry
.global NtNotifyChangeDirectoryFile
.global NtNotifyChangeDirectoryFileEx
.global NtNotifyChangeKey
.global NtNotifyChangeMultipleKeys
.global NtNotifyChangeSession
.global NtOpenEnlistment
.global NtOpenEventPair
.global NtOpenIoCompletion
.global NtOpenJobObject
.global NtOpenKeyEx
.global NtOpenKeyTransacted
.global NtOpenKeyTransactedEx
.global NtOpenKeyedEvent
.global NtOpenMutant
.global NtOpenObjectAuditAlarm
.global NtOpenPartition
.global NtOpenPrivateNamespace
.global NtOpenProcessToken
.global NtOpenRegistryTransaction
.global NtOpenResourceManager
.global NtOpenSemaphore
.global NtOpenSession
.global NtOpenSymbolicLinkObject
.global NtOpenThread
.global NtOpenTimer
.global NtOpenTransaction
.global NtOpenTransactionManager
.global NtPlugPlayControl
.global NtPrePrepareComplete
.global NtPrePrepareEnlistment
.global NtPrepareComplete
.global NtPrepareEnlistment
.global NtPrivilegeCheck
.global NtPrivilegeObjectAuditAlarm
.global NtPrivilegedServiceAuditAlarm
.global NtPropagationComplete
.global NtPropagationFailed
.global NtPulseEvent
.global NtQueryAuxiliaryCounterFrequency
.global NtQueryBootEntryOrder
.global NtQueryBootOptions
.global NtQueryDebugFilterState
.global NtQueryDirectoryFileEx
.global NtQueryDirectoryObject
.global NtQueryDriverEntryOrder
.global NtQueryEaFile
.global NtQueryFullAttributesFile
.global NtQueryInformationAtom
.global NtQueryInformationByName
.global NtQueryInformationEnlistment
.global NtQueryInformationJobObject
.global NtQueryInformationPort
.global NtQueryInformationResourceManager
.global NtQueryInformationTransaction
.global NtQueryInformationTransactionManager
.global NtQueryInformationWorkerFactory
.global NtQueryInstallUILanguage
.global NtQueryIntervalProfile
.global NtQueryIoCompletion
.global NtQueryLicenseValue
.global NtQueryMultipleValueKey
.global NtQueryMutant
.global NtQueryOpenSubKeys
.global NtQueryOpenSubKeysEx
.global NtQueryPortInformationProcess
.global NtQueryQuotaInformationFile
.global NtQuerySecurityAttributesToken
.global NtQuerySecurityObject
.global NtQuerySecurityPolicy
.global NtQuerySemaphore
.global NtQuerySymbolicLinkObject
.global NtQuerySystemEnvironmentValue
.global NtQuerySystemEnvironmentValueEx
.global NtQuerySystemInformationEx
.global NtQueryTimerResolution
.global NtQueryWnfStateData
.global NtQueryWnfStateNameInformation
.global NtQueueApcThreadEx
.global NtRaiseException
.global NtRaiseHardError
.global NtReadOnlyEnlistment
.global NtRecoverEnlistment
.global NtRecoverResourceManager
.global NtRecoverTransactionManager
.global NtRegisterProtocolAddressInformation
.global NtRegisterThreadTerminatePort
.global NtReleaseKeyedEvent
.global NtReleaseWorkerFactoryWorker
.global NtRemoveIoCompletionEx
.global NtRemoveProcessDebug
.global NtRenameKey
.global NtRenameTransactionManager
.global NtReplaceKey
.global NtReplacePartitionUnit
.global NtReplyWaitReplyPort
.global NtRequestPort
.global NtResetEvent
.global NtResetWriteWatch
.global NtRestoreKey
.global NtResumeProcess
.global NtRevertContainerImpersonation
.global NtRollbackComplete
.global NtRollbackEnlistment
.global NtRollbackRegistryTransaction
.global NtRollbackTransaction
.global NtRollforwardTransactionManager
.global NtSaveKey
.global NtSaveKeyEx
.global NtSaveMergedKeys
.global NtSecureConnectPort
.global NtSerializeBoot
.global NtSetBootEntryOrder
.global NtSetBootOptions
.global NtSetCachedSigningLevel
.global NtSetCachedSigningLevel2
.global NtSetContextThread
.global NtSetDebugFilterState
.global NtSetDefaultHardErrorPort
.global NtSetDefaultLocale
.global NtSetDefaultUILanguage
.global NtSetDriverEntryOrder
.global NtSetEaFile
.global NtSetHighEventPair
.global NtSetHighWaitLowEventPair
.global NtSetIRTimer
.global NtSetInformationDebugObject
.global NtSetInformationEnlistment
.global NtSetInformationJobObject
.global NtSetInformationKey
.global NtSetInformationResourceManager
.global NtSetInformationSymbolicLink
.global NtSetInformationToken
.global NtSetInformationTransaction
.global NtSetInformationTransactionManager
.global NtSetInformationVirtualMemory
.global NtSetInformationWorkerFactory
.global NtSetIntervalProfile
.global NtSetIoCompletion
.global NtSetIoCompletionEx
.global NtSetLdtEntries
.global NtSetLowEventPair
.global NtSetLowWaitHighEventPair
.global NtSetQuotaInformationFile
.global NtSetSecurityObject
.global NtSetSystemEnvironmentValue
.global NtSetSystemEnvironmentValueEx
.global NtSetSystemInformation
.global NtSetSystemPowerState
.global NtSetSystemTime
.global NtSetThreadExecutionState
.global NtSetTimer2
.global NtSetTimerEx
.global NtSetTimerResolution
.global NtSetUuidSeed
.global NtSetVolumeInformationFile
.global NtSetWnfProcessNotificationEvent
.global NtShutdownSystem
.global NtShutdownWorkerFactory
.global NtSignalAndWaitForSingleObject
.global NtSinglePhaseReject
.global NtStartProfile
.global NtStopProfile
.global NtSubscribeWnfStateChange
.global NtSuspendProcess
.global NtSuspendThread
.global NtSystemDebugControl
.global NtTerminateEnclave
.global NtTerminateJobObject
.global NtTestAlert
.global NtThawRegistry
.global NtThawTransactions
.global NtTraceControl
.global NtTranslateFilePath
.global NtUmsThreadYield
.global NtUnloadDriver
.global NtUnloadKey
.global NtUnloadKey2
.global NtUnloadKeyEx
.global NtUnlockFile
.global NtUnlockVirtualMemory
.global NtUnmapViewOfSectionEx
.global NtUnsubscribeWnfStateChange
.global NtUpdateWnfStateData
.global NtVdmControl
.global NtWaitForAlertByThreadId
.global NtWaitForDebugEvent
.global NtWaitForKeyedEvent
.global NtWaitForWorkViaWorkerFactory
.global NtWaitHighEventPair
.global NtWaitLowEventPair
.global NtAcquireCMFViewOwnership
.global NtCancelDeviceWakeupRequest
.global NtClearAllSavepointsTransaction
.global NtClearSavepointTransaction
.global NtRollbackSavepointTransaction
.global NtSavepointTransaction
.global NtSavepointComplete
.global NtCreateSectionEx
.global NtCreateCrossVmEvent
.global NtGetPlugPlayEvent
.global NtListTransactions
.global NtMarshallTransaction
.global NtPullTransaction
.global NtReleaseCMFViewOwnership
.global NtWaitForWnfNotifications
.global NtStartTm
.global NtSetInformationProcess
.global NtRequestDeviceWakeup
.global NtRequestWakeupLatency
.global NtQuerySystemTime
.global NtManageHotPatch
.global NtContinueEx

.global WhisperMain
.extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    add rsp, 0x28
    mov rcx, [rsp+ 8]              # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        # Issue syscall
    ret

NtAccessCheck:
    mov dword ptr [currentHash + RIP], 0x02C9E332B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWorkerFactoryWorkerReady:
    mov dword ptr [currentHash + RIP], 0x003A27F57   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcceptConnectPort:
    mov dword ptr [currentHash + RIP], 0x02AB5391A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPagesScatter:
    mov dword ptr [currentHash + RIP], 0x08E649A02   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x0F559E2DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallbackReturn:
    mov dword ptr [currentHash + RIP], 0x06CF64F62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFile:
    mov dword ptr [currentHash + RIP], 0x066B86A12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeviceIoControlFile:
    mov dword ptr [currentHash + RIP], 0x025BCAE9D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFile:
    mov dword ptr [currentHash + RIP], 0x0CCFB8428   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletion:
    mov dword ptr [currentHash + RIP], 0x01F027FD0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseSemaphore:
    mov dword ptr [currentHash + RIP], 0x0F4181198   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePort:
    mov dword ptr [currentHash + RIP], 0x020B20926   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyPort:
    mov dword ptr [currentHash + RIP], 0x06EF06368   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationThread:
    mov dword ptr [currentHash + RIP], 0x06B5473F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEvent:
    mov dword ptr [currentHash + RIP], 0x07EE44768   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClose:
    mov dword ptr [currentHash + RIP], 0x094944D26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryObject:
    mov dword ptr [currentHash + RIP], 0x09CBC67D0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationFile:
    mov dword ptr [currentHash + RIP], 0x078DE6158   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKey:
    mov dword ptr [currentHash + RIP], 0x08ADEA579   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateValueKey:
    mov dword ptr [currentHash + RIP], 0x01E1A0189   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFindAtom:
    mov dword ptr [currentHash + RIP], 0x0D646D7D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultLocale:
    mov dword ptr [currentHash + RIP], 0x001204DF4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryKey:
    mov dword ptr [currentHash + RIP], 0x059ED7852   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryValueKey:
    mov dword ptr [currentHash + RIP], 0x01930F45A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00F812137   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationProcess:
    mov dword ptr [currentHash + RIP], 0x0812484AC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects32:
    mov dword ptr [currentHash + RIP], 0x07CEE7C39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFileGather:
    mov dword ptr [currentHash + RIP], 0x05FCE7517   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKey:
    mov dword ptr [currentHash + RIP], 0x04A0365A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x03B952177   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateClientOfPort:
    mov dword ptr [currentHash + RIP], 0x034B93726   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseMutant:
    mov dword ptr [currentHash + RIP], 0x0BA0387A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationToken:
    mov dword ptr [currentHash + RIP], 0x013A881AC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWaitReplyPort:
    mov dword ptr [currentHash + RIP], 0x0DAB42FD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x01F930501   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadToken:
    mov dword ptr [currentHash + RIP], 0x079D2734A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationThread:
    mov dword ptr [currentHash + RIP], 0x01C0BD6BD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcess:
    mov dword ptr [currentHash + RIP], 0x0412944B0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationFile:
    mov dword ptr [currentHash + RIP], 0x023244E22   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSection:
    mov dword ptr [currentHash + RIP], 0x0D64FF69D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x019BF1321   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSection:
    mov dword ptr [currentHash + RIP], 0x03AD21C5B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePortEx:
    mov dword ptr [currentHash + RIP], 0x0BB95EF49   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateProcess:
    mov dword ptr [currentHash + RIP], 0x0C1E25400   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEventBoostPriority:
    mov dword ptr [currentHash + RIP], 0x0C49F3EF3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFileScatter:
    mov dword ptr [currentHash + RIP], 0x017AC232F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadTokenEx:
    mov dword ptr [currentHash + RIP], 0x0029BD4C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessTokenEx:
    mov dword ptr [currentHash + RIP], 0x0989ADE24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPerformanceCounter:
    mov dword ptr [currentHash + RIP], 0x0F9751426   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateKey:
    mov dword ptr [currentHash + RIP], 0x04B3E6A96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenFile:
    mov dword ptr [currentHash + RIP], 0x0D691DC26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDelayExecution:
    mov dword ptr [currentHash + RIP], 0x004961FE3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFile:
    mov dword ptr [currentHash + RIP], 0x060BA6202   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformation:
    mov dword ptr [currentHash + RIP], 0x09C33BCA1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSection:
    mov dword ptr [currentHash + RIP], 0x0F4EF17F2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimer:
    mov dword ptr [currentHash + RIP], 0x0EA5AE4D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFsControlFile:
    mov dword ptr [currentHash + RIP], 0x0303B2989   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00595031B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCloseObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x0923594A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateObject:
    mov dword ptr [currentHash + RIP], 0x00EA6E68D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAttributesFile:
    mov dword ptr [currentHash + RIP], 0x0E670E6EA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearEvent:
    mov dword ptr [currentHash + RIP], 0x0A0B3A925   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00D961311   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEvent:
    mov dword ptr [currentHash + RIP], 0x0D9732600   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustPrivilegesToken:
    mov dword ptr [currentHash + RIP], 0x0A1A53085   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateToken:
    mov dword ptr [currentHash + RIP], 0x005309710   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinue:
    mov dword ptr [currentHash + RIP], 0x0BF16AA99   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultUILanguage:
    mov dword ptr [currentHash + RIP], 0x09331CF0A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThread:
    mov dword ptr [currentHash + RIP], 0x00830469A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtYieldExecution:
    mov dword ptr [currentHash + RIP], 0x0FC4FBAFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtom:
    mov dword ptr [currentHash + RIP], 0x024760726   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEvent:
    mov dword ptr [currentHash + RIP], 0x01A3C9C2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVolumeInformationFile:
    mov dword ptr [currentHash + RIP], 0x0A1274927   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSection:
    mov dword ptr [currentHash + RIP], 0x0E30CE39A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFile:
    mov dword ptr [currentHash + RIP], 0x02FBCF185   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtApphelpCacheControl:
    mov dword ptr [currentHash + RIP], 0x00B5E7B8D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcessEx:
    mov dword ptr [currentHash + RIP], 0x09F95D341   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThread:
    mov dword ptr [currentHash + RIP], 0x0248F3E30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsProcessInJob:
    mov dword ptr [currentHash + RIP], 0x0D4ADDE06   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtProtectVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x041AC3D5B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySection:
    mov dword ptr [currentHash + RIP], 0x00F4C03EF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeThread:
    mov dword ptr [currentHash + RIP], 0x0E2806CA1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateThread:
    mov dword ptr [currentHash + RIP], 0x00EAE5467   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadRequestData:
    mov dword ptr [currentHash + RIP], 0x0A20A7A30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateFile:
    mov dword ptr [currentHash + RIP], 0x0ABBA21AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEvent:
    mov dword ptr [currentHash + RIP], 0x01EDBF680   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteRequestData:
    mov dword ptr [currentHash + RIP], 0x05C92A8C0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x08897EA68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x092345460   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects:
    mov dword ptr [currentHash + RIP], 0x0339D4373   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationObject:
    mov dword ptr [currentHash + RIP], 0x08AA679AA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFile:
    mov dword ptr [currentHash + RIP], 0x05AC36C5E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceEvent:
    mov dword ptr [currentHash + RIP], 0x0BE08A4AE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPowerInformation:
    mov dword ptr [currentHash + RIP], 0x08F126A00   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetValueKey:
    mov dword ptr [currentHash + RIP], 0x00F9AE984   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer:
    mov dword ptr [currentHash + RIP], 0x01BA78EA3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer:
    mov dword ptr [currentHash + RIP], 0x043975514   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByType:
    mov dword ptr [currentHash + RIP], 0x01CDA026E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultList:
    mov dword ptr [currentHash + RIP], 0x0A33B2326   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x014CA96D6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword ptr [currentHash + RIP], 0x068353E06   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireProcessActivityReference:
    mov dword ptr [currentHash + RIP], 0x052DF4F46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtomEx:
    mov dword ptr [currentHash + RIP], 0x0AB50F7B5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddBootEntry:
    mov dword ptr [currentHash + RIP], 0x009981900   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddDriverEntry:
    mov dword ptr [currentHash + RIP], 0x011980110   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustGroupsToken:
    mov dword ptr [currentHash + RIP], 0x005D1591C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustTokenClaimsAndDeviceGroups:
    mov dword ptr [currentHash + RIP], 0x0871C8385   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertResumeThread:
    mov dword ptr [currentHash + RIP], 0x015AF5106   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThread:
    mov dword ptr [currentHash + RIP], 0x0102F9E05   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThreadByThreadId:
    mov dword ptr [currentHash + RIP], 0x040B96E7A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateLocallyUniqueId:
    mov dword ptr [currentHash + RIP], 0x093BB581C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateReserveObject:
    mov dword ptr [currentHash + RIP], 0x0173561B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x089A2A018   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUuids:
    mov dword ptr [currentHash + RIP], 0x02DF55339   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemoryEx:
    mov dword ptr [currentHash + RIP], 0x0A0B61C93   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcAcceptConnectPort:
    mov dword ptr [currentHash + RIP], 0x0E572FAE1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCancelMessage:
    mov dword ptr [currentHash + RIP], 0x03395420E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPort:
    mov dword ptr [currentHash + RIP], 0x01E8D0700   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPortEx:
    mov dword ptr [currentHash + RIP], 0x0118C5F4B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePort:
    mov dword ptr [currentHash + RIP], 0x03EB22B3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePortSection:
    mov dword ptr [currentHash + RIP], 0x004D90C43   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateResourceReserve:
    mov dword ptr [currentHash + RIP], 0x040D2B05F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSectionView:
    mov dword ptr [currentHash + RIP], 0x0AB358F6E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSecurityContext:
    mov dword ptr [currentHash + RIP], 0x010AEE4E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeletePortSection:
    mov dword ptr [currentHash + RIP], 0x0D841C6CD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteResourceReserve:
    mov dword ptr [currentHash + RIP], 0x0F65AA863   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSectionView:
    mov dword ptr [currentHash + RIP], 0x030903503   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSecurityContext:
    mov dword ptr [currentHash + RIP], 0x016820512   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDisconnectPort:
    mov dword ptr [currentHash + RIP], 0x0653163AB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientContainerOfPort:
    mov dword ptr [currentHash + RIP], 0x0AEA2D323   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientOfPort:
    mov dword ptr [currentHash + RIP], 0x021B23C3B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderProcess:
    mov dword ptr [currentHash + RIP], 0x0622253A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderThread:
    mov dword ptr [currentHash + RIP], 0x0148FD1A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformation:
    mov dword ptr [currentHash + RIP], 0x0089E2A13   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformationMessage:
    mov dword ptr [currentHash + RIP], 0x0EDCDB872   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcRevokeSecurityContext:
    mov dword ptr [currentHash + RIP], 0x07762820B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSendWaitReceivePort:
    mov dword ptr [currentHash + RIP], 0x022B3012C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSetInformation:
    mov dword ptr [currentHash + RIP], 0x04EDB684B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAreMappedFilesTheSame:
    mov dword ptr [currentHash + RIP], 0x01DB34B8E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssignProcessToJobObject:
    mov dword ptr [currentHash + RIP], 0x08A99FA65   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssociateWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x09CB98A24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallEnclave:
    mov dword ptr [currentHash + RIP], 0x0552A302A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFileEx:
    mov dword ptr [currentHash + RIP], 0x0069CB4A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelSynchronousIoFile:
    mov dword ptr [currentHash + RIP], 0x03B98BA82   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer2:
    mov dword ptr [currentHash + RIP], 0x0B8BC74AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x0782278BE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitComplete:
    mov dword ptr [currentHash + RIP], 0x038C00C6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitEnlistment:
    mov dword ptr [currentHash + RIP], 0x0F044EDD6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x004932405   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitTransaction:
    mov dword ptr [currentHash + RIP], 0x092D55F8E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompactKeys:
    mov dword ptr [currentHash + RIP], 0x0FB80EC2A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareObjects:
    mov dword ptr [currentHash + RIP], 0x09FD369BF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareSigningLevels:
    mov dword ptr [currentHash + RIP], 0x014CA7C2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareTokens:
    mov dword ptr [currentHash + RIP], 0x04DD06B0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompleteConnectPort:
    mov dword ptr [currentHash + RIP], 0x058F3BB9C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompressKey:
    mov dword ptr [currentHash + RIP], 0x025DD2042   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConnectPort:
    mov dword ptr [currentHash + RIP], 0x0E671FDDE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword ptr [currentHash + RIP], 0x06DD6BE97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDebugObject:
    mov dword ptr [currentHash + RIP], 0x0943BA083   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x07AD43439   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObjectEx:
    mov dword ptr [currentHash + RIP], 0x04CEB143A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnclave:
    mov dword ptr [currentHash + RIP], 0x09B39BE73   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnlistment:
    mov dword ptr [currentHash + RIP], 0x0DE52E7E4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEventPair:
    mov dword ptr [currentHash + RIP], 0x040934C0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIRTimer:
    mov dword ptr [currentHash + RIP], 0x02491D0EB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIoCompletion:
    mov dword ptr [currentHash + RIP], 0x03C9B1C15   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobObject:
    mov dword ptr [currentHash + RIP], 0x00DB1E7AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobSet:
    mov dword ptr [currentHash + RIP], 0x0B03EEA91   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyTransacted:
    mov dword ptr [currentHash + RIP], 0x018C94276   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x030B41928   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateLowBoxToken:
    mov dword ptr [currentHash + RIP], 0x0CF91C202   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMailslotFile:
    mov dword ptr [currentHash + RIP], 0x04E91A0DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMutant:
    mov dword ptr [currentHash + RIP], 0x0723577A3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateNamedPipeFile:
    mov dword ptr [currentHash + RIP], 0x022252282   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePagingFile:
    mov dword ptr [currentHash + RIP], 0x00E814C24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePartition:
    mov dword ptr [currentHash + RIP], 0x0BEA7D03B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePort:
    mov dword ptr [currentHash + RIP], 0x0AFBDD24D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x06CD612C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcess:
    mov dword ptr [currentHash + RIP], 0x0379C3806   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfile:
    mov dword ptr [currentHash + RIP], 0x0C89BC821   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfileEx:
    mov dword ptr [currentHash + RIP], 0x002BBC5E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x052CC7019   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateResourceManager:
    mov dword ptr [currentHash + RIP], 0x04D97553A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSemaphore:
    mov dword ptr [currentHash + RIP], 0x09B0AEFE3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x00E987251   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThreadEx:
    mov dword ptr [currentHash + RIP], 0x092BEDC68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer:
    mov dword ptr [currentHash + RIP], 0x01F9BEA10   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer2:
    mov dword ptr [currentHash + RIP], 0x00F84835A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateToken:
    mov dword ptr [currentHash + RIP], 0x00F99E602   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTokenEx:
    mov dword ptr [currentHash + RIP], 0x06784BBC0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransaction:
    mov dword ptr [currentHash + RIP], 0x03ACADB59   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransactionManager:
    mov dword ptr [currentHash + RIP], 0x0042E3CA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateUserProcess:
    mov dword ptr [currentHash + RIP], 0x0872D9F40   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x0BC9A96C4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitablePort:
    mov dword ptr [currentHash + RIP], 0x024F8AEE6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWnfStateName:
    mov dword ptr [currentHash + RIP], 0x0B7109850   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x001561FD0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugActiveProcess:
    mov dword ptr [currentHash + RIP], 0x0E343C0ED   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugContinue:
    mov dword ptr [currentHash + RIP], 0x07D074CB4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteAtom:
    mov dword ptr [currentHash + RIP], 0x035BBD4A9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteBootEntry:
    mov dword ptr [currentHash + RIP], 0x00195F4EB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteDriverEntry:
    mov dword ptr [currentHash + RIP], 0x019966F68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteFile:
    mov dword ptr [currentHash + RIP], 0x03D3C2A80   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteKey:
    mov dword ptr [currentHash + RIP], 0x0665B11A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x012B41E2A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeletePrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x02D0D36AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteValueKey:
    mov dword ptr [currentHash + RIP], 0x03A2F1598   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateData:
    mov dword ptr [currentHash + RIP], 0x08E877890   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateName:
    mov dword ptr [currentHash + RIP], 0x0746AEB51   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisableLastKnownGood:
    mov dword ptr [currentHash + RIP], 0x02FB8B58E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisplayString:
    mov dword ptr [currentHash + RIP], 0x00C90C0C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDrawText:
    mov dword ptr [currentHash + RIP], 0x0F74EC0E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnableLastKnownGood:
    mov dword ptr [currentHash + RIP], 0x0F82EEE87   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateBootEntries:
    mov dword ptr [currentHash + RIP], 0x0E45CC1C3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateDriverEntries:
    mov dword ptr [currentHash + RIP], 0x03C8C4D6F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateSystemEnvironmentValuesEx:
    mov dword ptr [currentHash + RIP], 0x0B34A85F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateTransactionObject:
    mov dword ptr [currentHash + RIP], 0x084A867D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtExtendSection:
    mov dword ptr [currentHash + RIP], 0x000CB3E67   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterBootOption:
    mov dword ptr [currentHash + RIP], 0x09405F6D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterToken:
    mov dword ptr [currentHash + RIP], 0x003117798   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterTokenEx:
    mov dword ptr [currentHash + RIP], 0x07489A8DC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFileEx:
    mov dword ptr [currentHash + RIP], 0x0D6260C84   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstallUILanguage:
    mov dword ptr [currentHash + RIP], 0x0FDCACE96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstructionCache:
    mov dword ptr [currentHash + RIP], 0x00D334E15   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushKey:
    mov dword ptr [currentHash + RIP], 0x0152778D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushProcessWriteBuffers:
    mov dword ptr [currentHash + RIP], 0x002D882C0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x04390356F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushWriteBuffer:
    mov dword ptr [currentHash + RIP], 0x003BF6B65   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x0F74DD4F2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeRegistry:
    mov dword ptr [currentHash + RIP], 0x0F0AD35E0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeTransactions:
    mov dword ptr [currentHash + RIP], 0x00792D5D5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCachedSigningLevel:
    mov dword ptr [currentHash + RIP], 0x0BEFAB868   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCompleteWnfStateSubscription:
    mov dword ptr [currentHash + RIP], 0x04E864A1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetContextThread:
    mov dword ptr [currentHash + RIP], 0x018B0420D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumber:
    mov dword ptr [currentHash + RIP], 0x0143368D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumberEx:
    mov dword ptr [currentHash + RIP], 0x066EAA155   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetDevicePowerState:
    mov dword ptr [currentHash + RIP], 0x0623D946C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetMUIRegistryInfo:
    mov dword ptr [currentHash + RIP], 0x086059C8F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextProcess:
    mov dword ptr [currentHash + RIP], 0x041DB4254   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextThread:
    mov dword ptr [currentHash + RIP], 0x01409DF26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNlsSectionPtr:
    mov dword ptr [currentHash + RIP], 0x0A312280A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNotificationResourceManager:
    mov dword ptr [currentHash + RIP], 0x039012389   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetWriteWatch:
    mov dword ptr [currentHash + RIP], 0x01E232287   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateAnonymousToken:
    mov dword ptr [currentHash + RIP], 0x003961D26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateThread:
    mov dword ptr [currentHash + RIP], 0x093379F9E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeEnclave:
    mov dword ptr [currentHash + RIP], 0x08F38AF73   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeNlsFiles:
    mov dword ptr [currentHash + RIP], 0x0E4413D0E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeRegistry:
    mov dword ptr [currentHash + RIP], 0x0DD4D283E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitiatePowerAction:
    mov dword ptr [currentHash + RIP], 0x0FA4C3A1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsSystemResumeAutomatic:
    mov dword ptr [currentHash + RIP], 0x03C087126   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsUILanguageComitted:
    mov dword ptr [currentHash + RIP], 0x0605C2171   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListenPort:
    mov dword ptr [currentHash + RIP], 0x060B36F30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadDriver:
    mov dword ptr [currentHash + RIP], 0x0F15E28F5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadEnclaveData:
    mov dword ptr [currentHash + RIP], 0x02281B4B4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadHotPatch:
    mov dword ptr [currentHash + RIP], 0x0928019A3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey:
    mov dword ptr [currentHash + RIP], 0x06ED28DA9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey2:
    mov dword ptr [currentHash + RIP], 0x0C7BC115C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKeyEx:
    mov dword ptr [currentHash + RIP], 0x0157AC126   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockFile:
    mov dword ptr [currentHash + RIP], 0x02883E127   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockProductActivationKeys:
    mov dword ptr [currentHash + RIP], 0x0AE34A5A1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockRegistryKey:
    mov dword ptr [currentHash + RIP], 0x02726C23A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0C44CCECC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakePermanentObject:
    mov dword ptr [currentHash + RIP], 0x074AF7433   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakeTemporaryObject:
    mov dword ptr [currentHash + RIP], 0x0FAA301CC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManagePartition:
    mov dword ptr [currentHash + RIP], 0x03A8C5A5B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapCMFModule:
    mov dword ptr [currentHash + RIP], 0x0B4DC9E4B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x08DBEBE3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSectionEx:
    mov dword ptr [currentHash + RIP], 0x058D31614   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyBootEntry:
    mov dword ptr [currentHash + RIP], 0x067F44350   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyDriverEntry:
    mov dword ptr [currentHash + RIP], 0x00998273E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFile:
    mov dword ptr [currentHash + RIP], 0x00C343AAC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFileEx:
    mov dword ptr [currentHash + RIP], 0x0AA98F44F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeKey:
    mov dword ptr [currentHash + RIP], 0x069F1524C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeMultipleKeys:
    mov dword ptr [currentHash + RIP], 0x026BA2B39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeSession:
    mov dword ptr [currentHash + RIP], 0x0438B2358   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEnlistment:
    mov dword ptr [currentHash + RIP], 0x0311170FB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEventPair:
    mov dword ptr [currentHash + RIP], 0x08632625F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenIoCompletion:
    mov dword ptr [currentHash + RIP], 0x0B52055B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenJobObject:
    mov dword ptr [currentHash + RIP], 0x006BA2C07   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyEx:
    mov dword ptr [currentHash + RIP], 0x0ADA6E373   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransacted:
    mov dword ptr [currentHash + RIP], 0x0C369F3B5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransactedEx:
    mov dword ptr [currentHash + RIP], 0x0C2DCF462   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x038BA00FE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenMutant:
    mov dword ptr [currentHash + RIP], 0x02E80491A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x02EAB0A7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPartition:
    mov dword ptr [currentHash + RIP], 0x036AED5BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x006B62935   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessToken:
    mov dword ptr [currentHash + RIP], 0x00997010E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x0009A020B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenResourceManager:
    mov dword ptr [currentHash + RIP], 0x0F1B1DF6D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSemaphore:
    mov dword ptr [currentHash + RIP], 0x04B5A1264   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSession:
    mov dword ptr [currentHash + RIP], 0x00F940F06   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x03886063B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThread:
    mov dword ptr [currentHash + RIP], 0x0785C7AF5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTimer:
    mov dword ptr [currentHash + RIP], 0x03590371C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransaction:
    mov dword ptr [currentHash + RIP], 0x0B2AC51FC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransactionManager:
    mov dword ptr [currentHash + RIP], 0x009B3715E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPlugPlayControl:
    mov dword ptr [currentHash + RIP], 0x0F066DCA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareComplete:
    mov dword ptr [currentHash + RIP], 0x048B5A6E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareEnlistment:
    mov dword ptr [currentHash + RIP], 0x039A5382F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareComplete:
    mov dword ptr [currentHash + RIP], 0x0B531A4BD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareEnlistment:
    mov dword ptr [currentHash + RIP], 0x08AB5AF03   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeCheck:
    mov dword ptr [currentHash + RIP], 0x0CA55E3C9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x0DC52D2CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegedServiceAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x0DAA5F27A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationComplete:
    mov dword ptr [currentHash + RIP], 0x03EA5D729   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationFailed:
    mov dword ptr [currentHash + RIP], 0x0CA98D225   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPulseEvent:
    mov dword ptr [currentHash + RIP], 0x01B0A7C90   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAuxiliaryCounterFrequency:
    mov dword ptr [currentHash + RIP], 0x099BD9C3E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0A01C7936   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootOptions:
    mov dword ptr [currentHash + RIP], 0x04FDB7741   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDebugFilterState:
    mov dword ptr [currentHash + RIP], 0x09E01F88C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFileEx:
    mov dword ptr [currentHash + RIP], 0x08AB84DE6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x06CBC6621   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDriverEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0633CBA97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEaFile:
    mov dword ptr [currentHash + RIP], 0x035637BC6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryFullAttributesFile:
    mov dword ptr [currentHash + RIP], 0x0D841C6E4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationAtom:
    mov dword ptr [currentHash + RIP], 0x075256BA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationByName:
    mov dword ptr [currentHash + RIP], 0x03AA210E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationEnlistment:
    mov dword ptr [currentHash + RIP], 0x01B9AFFF1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationJobObject:
    mov dword ptr [currentHash + RIP], 0x03AA43409   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationPort:
    mov dword ptr [currentHash + RIP], 0x07CB61924   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationResourceManager:
    mov dword ptr [currentHash + RIP], 0x002B3F7D0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransaction:
    mov dword ptr [currentHash + RIP], 0x006CE261D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransactionManager:
    mov dword ptr [currentHash + RIP], 0x00C36C46C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x00E9AF7DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInstallUILanguage:
    mov dword ptr [currentHash + RIP], 0x0FB4CE0F0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIntervalProfile:
    mov dword ptr [currentHash + RIP], 0x0291E23B8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIoCompletion:
    mov dword ptr [currentHash + RIP], 0x0248FA49D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryLicenseValue:
    mov dword ptr [currentHash + RIP], 0x040DB0F10   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMultipleValueKey:
    mov dword ptr [currentHash + RIP], 0x08185A23F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMutant:
    mov dword ptr [currentHash + RIP], 0x02EFA6F2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeys:
    mov dword ptr [currentHash + RIP], 0x0B1D4A4B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeysEx:
    mov dword ptr [currentHash + RIP], 0x09765CBB0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPortInformationProcess:
    mov dword ptr [currentHash + RIP], 0x061BD09A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryQuotaInformationFile:
    mov dword ptr [currentHash + RIP], 0x0E677AC50   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityAttributesToken:
    mov dword ptr [currentHash + RIP], 0x07DD7A47C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityObject:
    mov dword ptr [currentHash + RIP], 0x005BD4F62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityPolicy:
    mov dword ptr [currentHash + RIP], 0x096A1ABE5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySemaphore:
    mov dword ptr [currentHash + RIP], 0x0C511B7B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x01405FC79   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValue:
    mov dword ptr [currentHash + RIP], 0x01632F53A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValueEx:
    mov dword ptr [currentHash + RIP], 0x0E3083E5D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformationEx:
    mov dword ptr [currentHash + RIP], 0x09092C44E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimerResolution:
    mov dword ptr [currentHash + RIP], 0x048D02E05   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateData:
    mov dword ptr [currentHash + RIP], 0x05B1DA140   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateNameInformation:
    mov dword ptr [currentHash + RIP], 0x00E982C0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThreadEx:
    mov dword ptr [currentHash + RIP], 0x08AAAAC15   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseException:
    mov dword ptr [currentHash + RIP], 0x01C3CF56C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseHardError:
    mov dword ptr [currentHash + RIP], 0x001F10563   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadOnlyEnlistment:
    mov dword ptr [currentHash + RIP], 0x03867CA21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverEnlistment:
    mov dword ptr [currentHash + RIP], 0x061D89ABF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverResourceManager:
    mov dword ptr [currentHash + RIP], 0x03FA95770   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverTransactionManager:
    mov dword ptr [currentHash + RIP], 0x013228123   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterProtocolAddressInformation:
    mov dword ptr [currentHash + RIP], 0x0654DE663   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterThreadTerminatePort:
    mov dword ptr [currentHash + RIP], 0x05CB05938   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x08921AEB3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseWorkerFactoryWorker:
    mov dword ptr [currentHash + RIP], 0x0F851EEF5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletionEx:
    mov dword ptr [currentHash + RIP], 0x05AD26767   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveProcessDebug:
    mov dword ptr [currentHash + RIP], 0x0463B0BF0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameKey:
    mov dword ptr [currentHash + RIP], 0x097CCA460   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameTransactionManager:
    mov dword ptr [currentHash + RIP], 0x03E262CA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplaceKey:
    mov dword ptr [currentHash + RIP], 0x089D2BE63   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplacePartitionUnit:
    mov dword ptr [currentHash + RIP], 0x016AB3E30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReplyPort:
    mov dword ptr [currentHash + RIP], 0x0A435ABAE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestPort:
    mov dword ptr [currentHash + RIP], 0x022B258BC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetEvent:
    mov dword ptr [currentHash + RIP], 0x08ED58946   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetWriteWatch:
    mov dword ptr [currentHash + RIP], 0x03CA8464A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRestoreKey:
    mov dword ptr [currentHash + RIP], 0x07BBE9BD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeProcess:
    mov dword ptr [currentHash + RIP], 0x04FA5483E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRevertContainerImpersonation:
    mov dword ptr [currentHash + RIP], 0x00E90CCC3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackComplete:
    mov dword ptr [currentHash + RIP], 0x02F540BD4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackEnlistment:
    mov dword ptr [currentHash + RIP], 0x0B7ABB221   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x0C8922E02   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackTransaction:
    mov dword ptr [currentHash + RIP], 0x0004BC61B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollforwardTransactionManager:
    mov dword ptr [currentHash + RIP], 0x0AE329C8F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKey:
    mov dword ptr [currentHash + RIP], 0x0AB989C26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKeyEx:
    mov dword ptr [currentHash + RIP], 0x0B5B9FD78   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveMergedKeys:
    mov dword ptr [currentHash + RIP], 0x0EE55F9DF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSecureConnectPort:
    mov dword ptr [currentHash + RIP], 0x0E90CE293   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSerializeBoot:
    mov dword ptr [currentHash + RIP], 0x070206AAF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootEntryOrder:
    mov dword ptr [currentHash + RIP], 0x03F5CAD71   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootOptions:
    mov dword ptr [currentHash + RIP], 0x09D89D750   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel:
    mov dword ptr [currentHash + RIP], 0x00AC0285E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel2:
    mov dword ptr [currentHash + RIP], 0x054CADE0E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetContextThread:
    mov dword ptr [currentHash + RIP], 0x008A87A01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDebugFilterState:
    mov dword ptr [currentHash + RIP], 0x03E1DEF21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultHardErrorPort:
    mov dword ptr [currentHash + RIP], 0x05CCE5960   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultLocale:
    mov dword ptr [currentHash + RIP], 0x0519A6FCB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultUILanguage:
    mov dword ptr [currentHash + RIP], 0x0189A0A27   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDriverEntryOrder:
    mov dword ptr [currentHash + RIP], 0x007A83CE5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEaFile:
    mov dword ptr [currentHash + RIP], 0x0A2FA64A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighEventPair:
    mov dword ptr [currentHash + RIP], 0x024B00C05   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighWaitLowEventPair:
    mov dword ptr [currentHash + RIP], 0x023B13A26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIRTimer:
    mov dword ptr [currentHash + RIP], 0x021A23322   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationDebugObject:
    mov dword ptr [currentHash + RIP], 0x0EE33E6AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationEnlistment:
    mov dword ptr [currentHash + RIP], 0x007A81C3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationJobObject:
    mov dword ptr [currentHash + RIP], 0x014B80615   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationKey:
    mov dword ptr [currentHash + RIP], 0x03CD83F43   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationResourceManager:
    mov dword ptr [currentHash + RIP], 0x095A364A7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationSymbolicLink:
    mov dword ptr [currentHash + RIP], 0x0D847D6D6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationToken:
    mov dword ptr [currentHash + RIP], 0x01E50914E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransaction:
    mov dword ptr [currentHash + RIP], 0x0C996C938   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransactionManager:
    mov dword ptr [currentHash + RIP], 0x04FD34148   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x03BAB373F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x088179E7A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIntervalProfile:
    mov dword ptr [currentHash + RIP], 0x02DB9D43D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletion:
    mov dword ptr [currentHash + RIP], 0x09AD0BA05   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletionEx:
    mov dword ptr [currentHash + RIP], 0x0D6D4048E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLdtEntries:
    mov dword ptr [currentHash + RIP], 0x0EC8E3621   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowEventPair:
    mov dword ptr [currentHash + RIP], 0x082D18A4A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowWaitHighEventPair:
    mov dword ptr [currentHash + RIP], 0x010B43029   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetQuotaInformationFile:
    mov dword ptr [currentHash + RIP], 0x08536CBE3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSecurityObject:
    mov dword ptr [currentHash + RIP], 0x00D1F6986   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValue:
    mov dword ptr [currentHash + RIP], 0x0B8DE9D5E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValueEx:
    mov dword ptr [currentHash + RIP], 0x0BF81FD54   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemInformation:
    mov dword ptr [currentHash + RIP], 0x02441D522   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemPowerState:
    mov dword ptr [currentHash + RIP], 0x0708386CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemTime:
    mov dword ptr [currentHash + RIP], 0x0B435FFE3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetThreadExecutionState:
    mov dword ptr [currentHash + RIP], 0x0EE4DC8C4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer2:
    mov dword ptr [currentHash + RIP], 0x057D4F08D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerEx:
    mov dword ptr [currentHash + RIP], 0x00E84D426   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerResolution:
    mov dword ptr [currentHash + RIP], 0x00E902FDF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetUuidSeed:
    mov dword ptr [currentHash + RIP], 0x04862C14F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetVolumeInformationFile:
    mov dword ptr [currentHash + RIP], 0x0B238260E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetWnfProcessNotificationEvent:
    mov dword ptr [currentHash + RIP], 0x09012F98E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownSystem:
    mov dword ptr [currentHash + RIP], 0x00E5DD1ED   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x04494762C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSignalAndWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x0253F2DA2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSinglePhaseReject:
    mov dword ptr [currentHash + RIP], 0x016BD2E11   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartProfile:
    mov dword ptr [currentHash + RIP], 0x0EFB9C72C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStopProfile:
    mov dword ptr [currentHash + RIP], 0x0CB9B003D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSubscribeWnfStateChange:
    mov dword ptr [currentHash + RIP], 0x082C35F7B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendProcess:
    mov dword ptr [currentHash + RIP], 0x01DA1042C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendThread:
    mov dword ptr [currentHash + RIP], 0x02C9F220D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSystemDebugControl:
    mov dword ptr [currentHash + RIP], 0x0876885FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateEnclave:
    mov dword ptr [currentHash + RIP], 0x0BA2998A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateJobObject:
    mov dword ptr [currentHash + RIP], 0x020780925   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTestAlert:
    mov dword ptr [currentHash + RIP], 0x08C27A582   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawRegistry:
    mov dword ptr [currentHash + RIP], 0x01083180D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawTransactions:
    mov dword ptr [currentHash + RIP], 0x03BEF7F25   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceControl:
    mov dword ptr [currentHash + RIP], 0x0DC8ED816   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTranslateFilePath:
    mov dword ptr [currentHash + RIP], 0x08798B016   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUmsThreadYield:
    mov dword ptr [currentHash + RIP], 0x0E7B8EC1E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadDriver:
    mov dword ptr [currentHash + RIP], 0x0EAC7F36C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey:
    mov dword ptr [currentHash + RIP], 0x01DCDFFB6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey2:
    mov dword ptr [currentHash + RIP], 0x0ABD0440D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKeyEx:
    mov dword ptr [currentHash + RIP], 0x0F4783506   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockFile:
    mov dword ptr [currentHash + RIP], 0x0A13C9DBD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x073E2677D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSectionEx:
    mov dword ptr [currentHash + RIP], 0x0D28901D3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnsubscribeWnfStateChange:
    mov dword ptr [currentHash + RIP], 0x036A710FA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUpdateWnfStateData:
    mov dword ptr [currentHash + RIP], 0x062BD8CF0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtVdmControl:
    mov dword ptr [currentHash + RIP], 0x0DD8CF356   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForAlertByThreadId:
    mov dword ptr [currentHash + RIP], 0x08C505AEA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForDebugEvent:
    mov dword ptr [currentHash + RIP], 0x0715A42FC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x048CB4B5C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWorkViaWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x0E28E1BFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitHighEventPair:
    mov dword ptr [currentHash + RIP], 0x010983409   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitLowEventPair:
    mov dword ptr [currentHash + RIP], 0x02F01AD16   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireCMFViewOwnership:
    mov dword ptr [currentHash + RIP], 0x02893B1BA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelDeviceWakeupRequest:
    mov dword ptr [currentHash + RIP], 0x08D13A98C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearAllSavepointsTransaction:
    mov dword ptr [currentHash + RIP], 0x0C51B81C8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x08873BAD7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x01AB33C23   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x0E670989D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointComplete:
    mov dword ptr [currentHash + RIP], 0x004C92202   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSectionEx:
    mov dword ptr [currentHash + RIP], 0x00096F5EB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateCrossVmEvent:
    mov dword ptr [currentHash + RIP], 0x03EBB5968   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetPlugPlayEvent:
    mov dword ptr [currentHash + RIP], 0x010C83D68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListTransactions:
    mov dword ptr [currentHash + RIP], 0x05BC73D13   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMarshallTransaction:
    mov dword ptr [currentHash + RIP], 0x0014A2217   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPullTransaction:
    mov dword ptr [currentHash + RIP], 0x0F7AFD1E7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseCMFViewOwnership:
    mov dword ptr [currentHash + RIP], 0x07AAD7A3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWnfNotifications:
    mov dword ptr [currentHash + RIP], 0x039A9FAFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartTm:
    mov dword ptr [currentHash + RIP], 0x021AC7B02   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationProcess:
    mov dword ptr [currentHash + RIP], 0x08A2A95BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestDeviceWakeup:
    mov dword ptr [currentHash + RIP], 0x09B389FAC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWakeupLatency:
    mov dword ptr [currentHash + RIP], 0x002B66946   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemTime:
    mov dword ptr [currentHash + RIP], 0x0B52F9EBE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManageHotPatch:
    mov dword ptr [currentHash + RIP], 0x07E423460   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinueEx:
    mov dword ptr [currentHash + RIP], 0x0138F4354   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


