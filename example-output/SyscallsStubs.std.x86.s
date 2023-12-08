.intel_syntax noprefix

.text
.global _NtAccessCheck
.global _NtWorkerFactoryWorkerReady
.global _NtAcceptConnectPort
.global _NtMapUserPhysicalPagesScatter
.global _NtWaitForSingleObject
.global _NtCallbackReturn
.global _NtReadFile
.global _NtDeviceIoControlFile
.global _NtWriteFile
.global _NtRemoveIoCompletion
.global _NtReleaseSemaphore
.global _NtReplyWaitReceivePort
.global _NtReplyPort
.global _NtSetInformationThread
.global _NtSetEvent
.global _NtClose
.global _NtQueryObject
.global _NtQueryInformationFile
.global _NtOpenKey
.global _NtEnumerateValueKey
.global _NtFindAtom
.global _NtQueryDefaultLocale
.global _NtQueryKey
.global _NtQueryValueKey
.global _NtAllocateVirtualMemory
.global _NtQueryInformationProcess
.global _NtWaitForMultipleObjects32
.global _NtWriteFileGather
.global _NtCreateKey
.global _NtFreeVirtualMemory
.global _NtImpersonateClientOfPort
.global _NtReleaseMutant
.global _NtQueryInformationToken
.global _NtRequestWaitReplyPort
.global _NtQueryVirtualMemory
.global _NtOpenThreadToken
.global _NtQueryInformationThread
.global _NtOpenProcess
.global _NtSetInformationFile
.global _NtMapViewOfSection
.global _NtAccessCheckAndAuditAlarm
.global _NtUnmapViewOfSection
.global _NtReplyWaitReceivePortEx
.global _NtTerminateProcess
.global _NtSetEventBoostPriority
.global _NtReadFileScatter
.global _NtOpenThreadTokenEx
.global _NtOpenProcessTokenEx
.global _NtQueryPerformanceCounter
.global _NtEnumerateKey
.global _NtOpenFile
.global _NtDelayExecution
.global _NtQueryDirectoryFile
.global _NtQuerySystemInformation
.global _NtOpenSection
.global _NtQueryTimer
.global _NtFsControlFile
.global _NtWriteVirtualMemory
.global _NtCloseObjectAuditAlarm
.global _NtDuplicateObject
.global _NtQueryAttributesFile
.global _NtClearEvent
.global _NtReadVirtualMemory
.global _NtOpenEvent
.global _NtAdjustPrivilegesToken
.global _NtDuplicateToken
.global _NtContinue
.global _NtQueryDefaultUILanguage
.global _NtQueueApcThread
.global _NtYieldExecution
.global _NtAddAtom
.global _NtCreateEvent
.global _NtQueryVolumeInformationFile
.global _NtCreateSection
.global _NtFlushBuffersFile
.global _NtApphelpCacheControl
.global _NtCreateProcessEx
.global _NtCreateThread
.global _NtIsProcessInJob
.global _NtProtectVirtualMemory
.global _NtQuerySection
.global _NtResumeThread
.global _NtTerminateThread
.global _NtReadRequestData
.global _NtCreateFile
.global _NtQueryEvent
.global _NtWriteRequestData
.global _NtOpenDirectoryObject
.global _NtAccessCheckByTypeAndAuditAlarm
.global _NtWaitForMultipleObjects
.global _NtSetInformationObject
.global _NtCancelIoFile
.global _NtTraceEvent
.global _NtPowerInformation
.global _NtSetValueKey
.global _NtCancelTimer
.global _NtSetTimer
.global _NtAccessCheckByType
.global _NtAccessCheckByTypeResultList
.global _NtAccessCheckByTypeResultListAndAuditAlarm
.global _NtAccessCheckByTypeResultListAndAuditAlarmByHandle
.global _NtAcquireProcessActivityReference
.global _NtAddAtomEx
.global _NtAddBootEntry
.global _NtAddDriverEntry
.global _NtAdjustGroupsToken
.global _NtAdjustTokenClaimsAndDeviceGroups
.global _NtAlertResumeThread
.global _NtAlertThread
.global _NtAlertThreadByThreadId
.global _NtAllocateLocallyUniqueId
.global _NtAllocateReserveObject
.global _NtAllocateUserPhysicalPages
.global _NtAllocateUuids
.global _NtAllocateVirtualMemoryEx
.global _NtAlpcAcceptConnectPort
.global _NtAlpcCancelMessage
.global _NtAlpcConnectPort
.global _NtAlpcConnectPortEx
.global _NtAlpcCreatePort
.global _NtAlpcCreatePortSection
.global _NtAlpcCreateResourceReserve
.global _NtAlpcCreateSectionView
.global _NtAlpcCreateSecurityContext
.global _NtAlpcDeletePortSection
.global _NtAlpcDeleteResourceReserve
.global _NtAlpcDeleteSectionView
.global _NtAlpcDeleteSecurityContext
.global _NtAlpcDisconnectPort
.global _NtAlpcImpersonateClientContainerOfPort
.global _NtAlpcImpersonateClientOfPort
.global _NtAlpcOpenSenderProcess
.global _NtAlpcOpenSenderThread
.global _NtAlpcQueryInformation
.global _NtAlpcQueryInformationMessage
.global _NtAlpcRevokeSecurityContext
.global _NtAlpcSendWaitReceivePort
.global _NtAlpcSetInformation
.global _NtAreMappedFilesTheSame
.global _NtAssignProcessToJobObject
.global _NtAssociateWaitCompletionPacket
.global _NtCallEnclave
.global _NtCancelIoFileEx
.global _NtCancelSynchronousIoFile
.global _NtCancelTimer2
.global _NtCancelWaitCompletionPacket
.global _NtCommitComplete
.global _NtCommitEnlistment
.global _NtCommitRegistryTransaction
.global _NtCommitTransaction
.global _NtCompactKeys
.global _NtCompareObjects
.global _NtCompareSigningLevels
.global _NtCompareTokens
.global _NtCompleteConnectPort
.global _NtCompressKey
.global _NtConnectPort
.global _NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
.global _NtCreateDebugObject
.global _NtCreateDirectoryObject
.global _NtCreateDirectoryObjectEx
.global _NtCreateEnclave
.global _NtCreateEnlistment
.global _NtCreateEventPair
.global _NtCreateIRTimer
.global _NtCreateIoCompletion
.global _NtCreateJobObject
.global _NtCreateJobSet
.global _NtCreateKeyTransacted
.global _NtCreateKeyedEvent
.global _NtCreateLowBoxToken
.global _NtCreateMailslotFile
.global _NtCreateMutant
.global _NtCreateNamedPipeFile
.global _NtCreatePagingFile
.global _NtCreatePartition
.global _NtCreatePort
.global _NtCreatePrivateNamespace
.global _NtCreateProcess
.global _NtCreateProfile
.global _NtCreateProfileEx
.global _NtCreateRegistryTransaction
.global _NtCreateResourceManager
.global _NtCreateSemaphore
.global _NtCreateSymbolicLinkObject
.global _NtCreateThreadEx
.global _NtCreateTimer
.global _NtCreateTimer2
.global _NtCreateToken
.global _NtCreateTokenEx
.global _NtCreateTransaction
.global _NtCreateTransactionManager
.global _NtCreateUserProcess
.global _NtCreateWaitCompletionPacket
.global _NtCreateWaitablePort
.global _NtCreateWnfStateName
.global _NtCreateWorkerFactory
.global _NtDebugActiveProcess
.global _NtDebugContinue
.global _NtDeleteAtom
.global _NtDeleteBootEntry
.global _NtDeleteDriverEntry
.global _NtDeleteFile
.global _NtDeleteKey
.global _NtDeleteObjectAuditAlarm
.global _NtDeletePrivateNamespace
.global _NtDeleteValueKey
.global _NtDeleteWnfStateData
.global _NtDeleteWnfStateName
.global _NtDisableLastKnownGood
.global _NtDisplayString
.global _NtDrawText
.global _NtEnableLastKnownGood
.global _NtEnumerateBootEntries
.global _NtEnumerateDriverEntries
.global _NtEnumerateSystemEnvironmentValuesEx
.global _NtEnumerateTransactionObject
.global _NtExtendSection
.global _NtFilterBootOption
.global _NtFilterToken
.global _NtFilterTokenEx
.global _NtFlushBuffersFileEx
.global _NtFlushInstallUILanguage
.global _NtFlushInstructionCache
.global _NtFlushKey
.global _NtFlushProcessWriteBuffers
.global _NtFlushVirtualMemory
.global _NtFlushWriteBuffer
.global _NtFreeUserPhysicalPages
.global _NtFreezeRegistry
.global _NtFreezeTransactions
.global _NtGetCachedSigningLevel
.global _NtGetCompleteWnfStateSubscription
.global _NtGetContextThread
.global _NtGetCurrentProcessorNumber
.global _NtGetCurrentProcessorNumberEx
.global _NtGetDevicePowerState
.global _NtGetMUIRegistryInfo
.global _NtGetNextProcess
.global _NtGetNextThread
.global _NtGetNlsSectionPtr
.global _NtGetNotificationResourceManager
.global _NtGetWriteWatch
.global _NtImpersonateAnonymousToken
.global _NtImpersonateThread
.global _NtInitializeEnclave
.global _NtInitializeNlsFiles
.global _NtInitializeRegistry
.global _NtInitiatePowerAction
.global _NtIsSystemResumeAutomatic
.global _NtIsUILanguageComitted
.global _NtListenPort
.global _NtLoadDriver
.global _NtLoadEnclaveData
.global _NtLoadHotPatch
.global _NtLoadKey
.global _NtLoadKey2
.global _NtLoadKeyEx
.global _NtLockFile
.global _NtLockProductActivationKeys
.global _NtLockRegistryKey
.global _NtLockVirtualMemory
.global _NtMakePermanentObject
.global _NtMakeTemporaryObject
.global _NtManagePartition
.global _NtMapCMFModule
.global _NtMapUserPhysicalPages
.global _NtMapViewOfSectionEx
.global _NtModifyBootEntry
.global _NtModifyDriverEntry
.global _NtNotifyChangeDirectoryFile
.global _NtNotifyChangeDirectoryFileEx
.global _NtNotifyChangeKey
.global _NtNotifyChangeMultipleKeys
.global _NtNotifyChangeSession
.global _NtOpenEnlistment
.global _NtOpenEventPair
.global _NtOpenIoCompletion
.global _NtOpenJobObject
.global _NtOpenKeyEx
.global _NtOpenKeyTransacted
.global _NtOpenKeyTransactedEx
.global _NtOpenKeyedEvent
.global _NtOpenMutant
.global _NtOpenObjectAuditAlarm
.global _NtOpenPartition
.global _NtOpenPrivateNamespace
.global _NtOpenProcessToken
.global _NtOpenRegistryTransaction
.global _NtOpenResourceManager
.global _NtOpenSemaphore
.global _NtOpenSession
.global _NtOpenSymbolicLinkObject
.global _NtOpenThread
.global _NtOpenTimer
.global _NtOpenTransaction
.global _NtOpenTransactionManager
.global _NtPlugPlayControl
.global _NtPrePrepareComplete
.global _NtPrePrepareEnlistment
.global _NtPrepareComplete
.global _NtPrepareEnlistment
.global _NtPrivilegeCheck
.global _NtPrivilegeObjectAuditAlarm
.global _NtPrivilegedServiceAuditAlarm
.global _NtPropagationComplete
.global _NtPropagationFailed
.global _NtPulseEvent
.global _NtQueryAuxiliaryCounterFrequency
.global _NtQueryBootEntryOrder
.global _NtQueryBootOptions
.global _NtQueryDebugFilterState
.global _NtQueryDirectoryFileEx
.global _NtQueryDirectoryObject
.global _NtQueryDriverEntryOrder
.global _NtQueryEaFile
.global _NtQueryFullAttributesFile
.global _NtQueryInformationAtom
.global _NtQueryInformationByName
.global _NtQueryInformationEnlistment
.global _NtQueryInformationJobObject
.global _NtQueryInformationPort
.global _NtQueryInformationResourceManager
.global _NtQueryInformationTransaction
.global _NtQueryInformationTransactionManager
.global _NtQueryInformationWorkerFactory
.global _NtQueryInstallUILanguage
.global _NtQueryIntervalProfile
.global _NtQueryIoCompletion
.global _NtQueryLicenseValue
.global _NtQueryMultipleValueKey
.global _NtQueryMutant
.global _NtQueryOpenSubKeys
.global _NtQueryOpenSubKeysEx
.global _NtQueryPortInformationProcess
.global _NtQueryQuotaInformationFile
.global _NtQuerySecurityAttributesToken
.global _NtQuerySecurityObject
.global _NtQuerySecurityPolicy
.global _NtQuerySemaphore
.global _NtQuerySymbolicLinkObject
.global _NtQuerySystemEnvironmentValue
.global _NtQuerySystemEnvironmentValueEx
.global _NtQuerySystemInformationEx
.global _NtQueryTimerResolution
.global _NtQueryWnfStateData
.global _NtQueryWnfStateNameInformation
.global _NtQueueApcThreadEx
.global _NtRaiseException
.global _NtRaiseHardError
.global _NtReadOnlyEnlistment
.global _NtRecoverEnlistment
.global _NtRecoverResourceManager
.global _NtRecoverTransactionManager
.global _NtRegisterProtocolAddressInformation
.global _NtRegisterThreadTerminatePort
.global _NtReleaseKeyedEvent
.global _NtReleaseWorkerFactoryWorker
.global _NtRemoveIoCompletionEx
.global _NtRemoveProcessDebug
.global _NtRenameKey
.global _NtRenameTransactionManager
.global _NtReplaceKey
.global _NtReplacePartitionUnit
.global _NtReplyWaitReplyPort
.global _NtRequestPort
.global _NtResetEvent
.global _NtResetWriteWatch
.global _NtRestoreKey
.global _NtResumeProcess
.global _NtRevertContainerImpersonation
.global _NtRollbackComplete
.global _NtRollbackEnlistment
.global _NtRollbackRegistryTransaction
.global _NtRollbackTransaction
.global _NtRollforwardTransactionManager
.global _NtSaveKey
.global _NtSaveKeyEx
.global _NtSaveMergedKeys
.global _NtSecureConnectPort
.global _NtSerializeBoot
.global _NtSetBootEntryOrder
.global _NtSetBootOptions
.global _NtSetCachedSigningLevel
.global _NtSetCachedSigningLevel2
.global _NtSetContextThread
.global _NtSetDebugFilterState
.global _NtSetDefaultHardErrorPort
.global _NtSetDefaultLocale
.global _NtSetDefaultUILanguage
.global _NtSetDriverEntryOrder
.global _NtSetEaFile
.global _NtSetHighEventPair
.global _NtSetHighWaitLowEventPair
.global _NtSetIRTimer
.global _NtSetInformationDebugObject
.global _NtSetInformationEnlistment
.global _NtSetInformationJobObject
.global _NtSetInformationKey
.global _NtSetInformationResourceManager
.global _NtSetInformationSymbolicLink
.global _NtSetInformationToken
.global _NtSetInformationTransaction
.global _NtSetInformationTransactionManager
.global _NtSetInformationVirtualMemory
.global _NtSetInformationWorkerFactory
.global _NtSetIntervalProfile
.global _NtSetIoCompletion
.global _NtSetIoCompletionEx
.global _NtSetLdtEntries
.global _NtSetLowEventPair
.global _NtSetLowWaitHighEventPair
.global _NtSetQuotaInformationFile
.global _NtSetSecurityObject
.global _NtSetSystemEnvironmentValue
.global _NtSetSystemEnvironmentValueEx
.global _NtSetSystemInformation
.global _NtSetSystemPowerState
.global _NtSetSystemTime
.global _NtSetThreadExecutionState
.global _NtSetTimer2
.global _NtSetTimerEx
.global _NtSetTimerResolution
.global _NtSetUuidSeed
.global _NtSetVolumeInformationFile
.global _NtSetWnfProcessNotificationEvent
.global _NtShutdownSystem
.global _NtShutdownWorkerFactory
.global _NtSignalAndWaitForSingleObject
.global _NtSinglePhaseReject
.global _NtStartProfile
.global _NtStopProfile
.global _NtSubscribeWnfStateChange
.global _NtSuspendProcess
.global _NtSuspendThread
.global _NtSystemDebugControl
.global _NtTerminateEnclave
.global _NtTerminateJobObject
.global _NtTestAlert
.global _NtThawRegistry
.global _NtThawTransactions
.global _NtTraceControl
.global _NtTranslateFilePath
.global _NtUmsThreadYield
.global _NtUnloadDriver
.global _NtUnloadKey
.global _NtUnloadKey2
.global _NtUnloadKeyEx
.global _NtUnlockFile
.global _NtUnlockVirtualMemory
.global _NtUnmapViewOfSectionEx
.global _NtUnsubscribeWnfStateChange
.global _NtUpdateWnfStateData
.global _NtVdmControl
.global _NtWaitForAlertByThreadId
.global _NtWaitForDebugEvent
.global _NtWaitForKeyedEvent
.global _NtWaitForWorkViaWorkerFactory
.global _NtWaitHighEventPair
.global _NtWaitLowEventPair
.global _NtAcquireCMFViewOwnership
.global _NtCancelDeviceWakeupRequest
.global _NtClearAllSavepointsTransaction
.global _NtClearSavepointTransaction
.global _NtRollbackSavepointTransaction
.global _NtSavepointTransaction
.global _NtSavepointComplete
.global _NtCreateSectionEx
.global _NtCreateCrossVmEvent
.global _NtGetPlugPlayEvent
.global _NtListTransactions
.global _NtMarshallTransaction
.global _NtPullTransaction
.global _NtReleaseCMFViewOwnership
.global _NtWaitForWnfNotifications
.global _NtStartTm
.global _NtSetInformationProcess
.global _NtRequestDeviceWakeup
.global _NtRequestWakeupLatency
.global _NtQuerySystemTime
.global _NtManageHotPatch
.global _NtContinueEx

.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
    ret

_NtAccessCheck:
    push 0x2C9E332B
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x03A27F57
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x2AB5391A
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0x8E649A02
    call _WhisperMain

_NtWaitForSingleObject:
    push 0xF559E2DA
    call _WhisperMain

_NtCallbackReturn:
    push 0x6CF64F62
    call _WhisperMain

_NtReadFile:
    push 0x66B86A12
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0x25BCAE9D
    call _WhisperMain

_NtWriteFile:
    push 0xCCFB8428
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x1F027FD0
    call _WhisperMain

_NtReleaseSemaphore:
    push 0xF4181198
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x20B20926
    call _WhisperMain

_NtReplyPort:
    push 0x6EF06368
    call _WhisperMain

_NtSetInformationThread:
    push 0x6B5473F7
    call _WhisperMain

_NtSetEvent:
    push 0x7EE44768
    call _WhisperMain

_NtClose:
    push 0x94944D26
    call _WhisperMain

_NtQueryObject:
    push 0x9CBC67D0
    call _WhisperMain

_NtQueryInformationFile:
    push 0x78DE6158
    call _WhisperMain

_NtOpenKey:
    push 0x8ADEA579
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x1E1A0189
    call _WhisperMain

_NtFindAtom:
    push 0xD646D7D4
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0x01204DF4
    call _WhisperMain

_NtQueryKey:
    push 0x59ED7852
    call _WhisperMain

_NtQueryValueKey:
    push 0x1930F45A
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x0F812137
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x812484AC
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x7CEE7C39
    call _WhisperMain

_NtWriteFileGather:
    push 0x5FCE7517
    call _WhisperMain

_NtCreateKey:
    push 0x4A0365A0
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x3B952177
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0x34B93726
    call _WhisperMain

_NtReleaseMutant:
    push 0xBA0387A2
    call _WhisperMain

_NtQueryInformationToken:
    push 0x13A881AC
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0xDAB42FD5
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0x1F930501
    call _WhisperMain

_NtOpenThreadToken:
    push 0x79D2734A
    call _WhisperMain

_NtQueryInformationThread:
    push 0x1C0BD6BD
    call _WhisperMain

_NtOpenProcess:
    push 0x412944B0
    call _WhisperMain

_NtSetInformationFile:
    push 0x23244E22
    call _WhisperMain

_NtMapViewOfSection:
    push 0xD64FF69D
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0x19BF1321
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0x3AD21C5B
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0xBB95EF49
    call _WhisperMain

_NtTerminateProcess:
    push 0xC1E25400
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0xC49F3EF3
    call _WhisperMain

_NtReadFileScatter:
    push 0x17AC232F
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x029BD4C5
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x989ADE24
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0xF9751426
    call _WhisperMain

_NtEnumerateKey:
    push 0x4B3E6A96
    call _WhisperMain

_NtOpenFile:
    push 0xD691DC26
    call _WhisperMain

_NtDelayExecution:
    push 0x04961FE3
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x60BA6202
    call _WhisperMain

_NtQuerySystemInformation:
    push 0x9C33BCA1
    call _WhisperMain

_NtOpenSection:
    push 0xF4EF17F2
    call _WhisperMain

_NtQueryTimer:
    push 0xEA5AE4D9
    call _WhisperMain

_NtFsControlFile:
    push 0x303B2989
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x0595031B
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x923594A0
    call _WhisperMain

_NtDuplicateObject:
    push 0x0EA6E68D
    call _WhisperMain

_NtQueryAttributesFile:
    push 0xE670E6EA
    call _WhisperMain

_NtClearEvent:
    push 0xA0B3A925
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x0D961311
    call _WhisperMain

_NtOpenEvent:
    push 0xD9732600
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0xA1A53085
    call _WhisperMain

_NtDuplicateToken:
    push 0x05309710
    call _WhisperMain

_NtContinue:
    push 0xBF16AA99
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0x9331CF0A
    call _WhisperMain

_NtQueueApcThread:
    push 0x0830469A
    call _WhisperMain

_NtYieldExecution:
    push 0xFC4FBAFB
    call _WhisperMain

_NtAddAtom:
    push 0x24760726
    call _WhisperMain

_NtCreateEvent:
    push 0x1A3C9C2E
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0xA1274927
    call _WhisperMain

_NtCreateSection:
    push 0xE30CE39A
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x2FBCF185
    call _WhisperMain

_NtApphelpCacheControl:
    push 0x0B5E7B8D
    call _WhisperMain

_NtCreateProcessEx:
    push 0x9F95D341
    call _WhisperMain

_NtCreateThread:
    push 0x248F3E30
    call _WhisperMain

_NtIsProcessInJob:
    push 0xD4ADDE06
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0x41AC3D5B
    call _WhisperMain

_NtQuerySection:
    push 0x0F4C03EF
    call _WhisperMain

_NtResumeThread:
    push 0xE2806CA1
    call _WhisperMain

_NtTerminateThread:
    push 0x0EAE5467
    call _WhisperMain

_NtReadRequestData:
    push 0xA20A7A30
    call _WhisperMain

_NtCreateFile:
    push 0xABBA21AD
    call _WhisperMain

_NtQueryEvent:
    push 0x1EDBF680
    call _WhisperMain

_NtWriteRequestData:
    push 0x5C92A8C0
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x8897EA68
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0x92345460
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0x339D4373
    call _WhisperMain

_NtSetInformationObject:
    push 0x8AA679AA
    call _WhisperMain

_NtCancelIoFile:
    push 0x5AC36C5E
    call _WhisperMain

_NtTraceEvent:
    push 0xBE08A4AE
    call _WhisperMain

_NtPowerInformation:
    push 0x8F126A00
    call _WhisperMain

_NtSetValueKey:
    push 0x0F9AE984
    call _WhisperMain

_NtCancelTimer:
    push 0x1BA78EA3
    call _WhisperMain

_NtSetTimer:
    push 0x43975514
    call _WhisperMain

_NtAccessCheckByType:
    push 0x1CDA026E
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0xA33B2326
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0x14CA96D6
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0x68353E06
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0x52DF4F46
    call _WhisperMain

_NtAddAtomEx:
    push 0xAB50F7B5
    call _WhisperMain

_NtAddBootEntry:
    push 0x09981900
    call _WhisperMain

_NtAddDriverEntry:
    push 0x11980110
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x05D1591C
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x871C8385
    call _WhisperMain

_NtAlertResumeThread:
    push 0x15AF5106
    call _WhisperMain

_NtAlertThread:
    push 0x102F9E05
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0x40B96E7A
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0x93BB581C
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x173561B7
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0x89A2A018
    call _WhisperMain

_NtAllocateUuids:
    push 0x2DF55339
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0xA0B61C93
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0xE572FAE1
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0x3395420E
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x1E8D0700
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x118C5F4B
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x3EB22B3A
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0x04D90C43
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x40D2B05F
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0xAB358F6E
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0x10AEE4E6
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0xD841C6CD
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0xF65AA863
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x30903503
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0x16820512
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x653163AB
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0xAEA2D323
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0x21B23C3B
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0x622253A0
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x148FD1A6
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x089E2A13
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0xEDCDB872
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0x7762820B
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x22B3012C
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x4EDB684B
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0x1DB34B8E
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x8A99FA65
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x9CB98A24
    call _WhisperMain

_NtCallEnclave:
    push 0x552A302A
    call _WhisperMain

_NtCancelIoFileEx:
    push 0x069CB4A6
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0x3B98BA82
    call _WhisperMain

_NtCancelTimer2:
    push 0xB8BC74AD
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0x782278BE
    call _WhisperMain

_NtCommitComplete:
    push 0x38C00C6A
    call _WhisperMain

_NtCommitEnlistment:
    push 0xF044EDD6
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0x04932405
    call _WhisperMain

_NtCommitTransaction:
    push 0x92D55F8E
    call _WhisperMain

_NtCompactKeys:
    push 0xFB80EC2A
    call _WhisperMain

_NtCompareObjects:
    push 0x9FD369BF
    call _WhisperMain

_NtCompareSigningLevels:
    push 0x14CA7C2E
    call _WhisperMain

_NtCompareTokens:
    push 0x4DD06B0B
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x58F3BB9C
    call _WhisperMain

_NtCompressKey:
    push 0x25DD2042
    call _WhisperMain

_NtConnectPort:
    push 0xE671FDDE
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x6DD6BE97
    call _WhisperMain

_NtCreateDebugObject:
    push 0x943BA083
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x7AD43439
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0x4CEB143A
    call _WhisperMain

_NtCreateEnclave:
    push 0x9B39BE73
    call _WhisperMain

_NtCreateEnlistment:
    push 0xDE52E7E4
    call _WhisperMain

_NtCreateEventPair:
    push 0x40934C0D
    call _WhisperMain

_NtCreateIRTimer:
    push 0x2491D0EB
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x3C9B1C15
    call _WhisperMain

_NtCreateJobObject:
    push 0x0DB1E7AF
    call _WhisperMain

_NtCreateJobSet:
    push 0xB03EEA91
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0x18C94276
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0x30B41928
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0xCF91C202
    call _WhisperMain

_NtCreateMailslotFile:
    push 0x4E91A0DA
    call _WhisperMain

_NtCreateMutant:
    push 0x723577A3
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x22252282
    call _WhisperMain

_NtCreatePagingFile:
    push 0x0E814C24
    call _WhisperMain

_NtCreatePartition:
    push 0xBEA7D03B
    call _WhisperMain

_NtCreatePort:
    push 0xAFBDD24D
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x6CD612C5
    call _WhisperMain

_NtCreateProcess:
    push 0x379C3806
    call _WhisperMain

_NtCreateProfile:
    push 0xC89BC821
    call _WhisperMain

_NtCreateProfileEx:
    push 0x02BBC5E5
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x52CC7019
    call _WhisperMain

_NtCreateResourceManager:
    push 0x4D97553A
    call _WhisperMain

_NtCreateSemaphore:
    push 0x9B0AEFE3
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x0E987251
    call _WhisperMain

_NtCreateThreadEx:
    push 0x92BEDC68
    call _WhisperMain

_NtCreateTimer:
    push 0x1F9BEA10
    call _WhisperMain

_NtCreateTimer2:
    push 0x0F84835A
    call _WhisperMain

_NtCreateToken:
    push 0x0F99E602
    call _WhisperMain

_NtCreateTokenEx:
    push 0x6784BBC0
    call _WhisperMain

_NtCreateTransaction:
    push 0x3ACADB59
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x042E3CA4
    call _WhisperMain

_NtCreateUserProcess:
    push 0x872D9F40
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0xBC9A96C4
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x24F8AEE6
    call _WhisperMain

_NtCreateWnfStateName:
    push 0xB7109850
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0x01561FD0
    call _WhisperMain

_NtDebugActiveProcess:
    push 0xE343C0ED
    call _WhisperMain

_NtDebugContinue:
    push 0x7D074CB4
    call _WhisperMain

_NtDeleteAtom:
    push 0x35BBD4A9
    call _WhisperMain

_NtDeleteBootEntry:
    push 0x0195F4EB
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0x19966F68
    call _WhisperMain

_NtDeleteFile:
    push 0x3D3C2A80
    call _WhisperMain

_NtDeleteKey:
    push 0x665B11A0
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x12B41E2A
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x2D0D36AD
    call _WhisperMain

_NtDeleteValueKey:
    push 0x3A2F1598
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0x8E877890
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0x746AEB51
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0x2FB8B58E
    call _WhisperMain

_NtDisplayString:
    push 0x0C90C0C5
    call _WhisperMain

_NtDrawText:
    push 0xF74EC0E5
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0xF82EEE87
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0xE45CC1C3
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x3C8C4D6F
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0xB34A85F7
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x84A867D4
    call _WhisperMain

_NtExtendSection:
    push 0x00CB3E67
    call _WhisperMain

_NtFilterBootOption:
    push 0x9405F6D9
    call _WhisperMain

_NtFilterToken:
    push 0x03117798
    call _WhisperMain

_NtFilterTokenEx:
    push 0x7489A8DC
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0xD6260C84
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0xFDCACE96
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x0D334E15
    call _WhisperMain

_NtFlushKey:
    push 0x152778D4
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0x02D882C0
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x4390356F
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0x03BF6B65
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0xF74DD4F2
    call _WhisperMain

_NtFreezeRegistry:
    push 0xF0AD35E0
    call _WhisperMain

_NtFreezeTransactions:
    push 0x0792D5D5
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0xBEFAB868
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x4E864A1F
    call _WhisperMain

_NtGetContextThread:
    push 0x18B0420D
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x143368D9
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0x66EAA155
    call _WhisperMain

_NtGetDevicePowerState:
    push 0x623D946C
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0x86059C8F
    call _WhisperMain

_NtGetNextProcess:
    push 0x41DB4254
    call _WhisperMain

_NtGetNextThread:
    push 0x1409DF26
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0xA312280A
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0x39012389
    call _WhisperMain

_NtGetWriteWatch:
    push 0x1E232287
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x03961D26
    call _WhisperMain

_NtImpersonateThread:
    push 0x93379F9E
    call _WhisperMain

_NtInitializeEnclave:
    push 0x8F38AF73
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0xE4413D0E
    call _WhisperMain

_NtInitializeRegistry:
    push 0xDD4D283E
    call _WhisperMain

_NtInitiatePowerAction:
    push 0xFA4C3A1F
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0x3C087126
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0x605C2171
    call _WhisperMain

_NtListenPort:
    push 0x60B36F30
    call _WhisperMain

_NtLoadDriver:
    push 0xF15E28F5
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x2281B4B4
    call _WhisperMain

_NtLoadHotPatch:
    push 0x928019A3
    call _WhisperMain

_NtLoadKey:
    push 0x6ED28DA9
    call _WhisperMain

_NtLoadKey2:
    push 0xC7BC115C
    call _WhisperMain

_NtLoadKeyEx:
    push 0x157AC126
    call _WhisperMain

_NtLockFile:
    push 0x2883E127
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0xAE34A5A1
    call _WhisperMain

_NtLockRegistryKey:
    push 0x2726C23A
    call _WhisperMain

_NtLockVirtualMemory:
    push 0xC44CCECC
    call _WhisperMain

_NtMakePermanentObject:
    push 0x74AF7433
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0xFAA301CC
    call _WhisperMain

_NtManagePartition:
    push 0x3A8C5A5B
    call _WhisperMain

_NtMapCMFModule:
    push 0xB4DC9E4B
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x8DBEBE3A
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0x58D31614
    call _WhisperMain

_NtModifyBootEntry:
    push 0x67F44350
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x0998273E
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0x0C343AAC
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0xAA98F44F
    call _WhisperMain

_NtNotifyChangeKey:
    push 0x69F1524C
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x26BA2B39
    call _WhisperMain

_NtNotifyChangeSession:
    push 0x438B2358
    call _WhisperMain

_NtOpenEnlistment:
    push 0x311170FB
    call _WhisperMain

_NtOpenEventPair:
    push 0x8632625F
    call _WhisperMain

_NtOpenIoCompletion:
    push 0xB52055B2
    call _WhisperMain

_NtOpenJobObject:
    push 0x06BA2C07
    call _WhisperMain

_NtOpenKeyEx:
    push 0xADA6E373
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0xC369F3B5
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0xC2DCF462
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0x38BA00FE
    call _WhisperMain

_NtOpenMutant:
    push 0x2E80491A
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x2EAB0A7C
    call _WhisperMain

_NtOpenPartition:
    push 0x36AED5BB
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0x06B62935
    call _WhisperMain

_NtOpenProcessToken:
    push 0x0997010E
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x009A020B
    call _WhisperMain

_NtOpenResourceManager:
    push 0xF1B1DF6D
    call _WhisperMain

_NtOpenSemaphore:
    push 0x4B5A1264
    call _WhisperMain

_NtOpenSession:
    push 0x0F940F06
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x3886063B
    call _WhisperMain

_NtOpenThread:
    push 0x785C7AF5
    call _WhisperMain

_NtOpenTimer:
    push 0x3590371C
    call _WhisperMain

_NtOpenTransaction:
    push 0xB2AC51FC
    call _WhisperMain

_NtOpenTransactionManager:
    push 0x09B3715E
    call _WhisperMain

_NtPlugPlayControl:
    push 0xF066DCA6
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x48B5A6E6
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0x39A5382F
    call _WhisperMain

_NtPrepareComplete:
    push 0xB531A4BD
    call _WhisperMain

_NtPrepareEnlistment:
    push 0x8AB5AF03
    call _WhisperMain

_NtPrivilegeCheck:
    push 0xCA55E3C9
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0xDC52D2CA
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0xDAA5F27A
    call _WhisperMain

_NtPropagationComplete:
    push 0x3EA5D729
    call _WhisperMain

_NtPropagationFailed:
    push 0xCA98D225
    call _WhisperMain

_NtPulseEvent:
    push 0x1B0A7C90
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0x99BD9C3E
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0xA01C7936
    call _WhisperMain

_NtQueryBootOptions:
    push 0x4FDB7741
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x9E01F88C
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0x8AB84DE6
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0x6CBC6621
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0x633CBA97
    call _WhisperMain

_NtQueryEaFile:
    push 0x35637BC6
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0xD841C6E4
    call _WhisperMain

_NtQueryInformationAtom:
    push 0x75256BA4
    call _WhisperMain

_NtQueryInformationByName:
    push 0x3AA210E5
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x1B9AFFF1
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0x3AA43409
    call _WhisperMain

_NtQueryInformationPort:
    push 0x7CB61924
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0x02B3F7D0
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x06CE261D
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0x0C36C46C
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0x0E9AF7DB
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0xFB4CE0F0
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0x291E23B8
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x248FA49D
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x40DB0F10
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0x8185A23F
    call _WhisperMain

_NtQueryMutant:
    push 0x2EFA6F2E
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0xB1D4A4B2
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x9765CBB0
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x61BD09A0
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0xE677AC50
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0x7DD7A47C
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x05BD4F62
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0x96A1ABE5
    call _WhisperMain

_NtQuerySemaphore:
    push 0xC511B7B7
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x1405FC79
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0x1632F53A
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0xE3083E5D
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0x9092C44E
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x48D02E05
    call _WhisperMain

_NtQueryWnfStateData:
    push 0x5B1DA140
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0x0E982C0D
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0x8AAAAC15
    call _WhisperMain

_NtRaiseException:
    push 0x1C3CF56C
    call _WhisperMain

_NtRaiseHardError:
    push 0x01F10563
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0x3867CA21
    call _WhisperMain

_NtRecoverEnlistment:
    push 0x61D89ABF
    call _WhisperMain

_NtRecoverResourceManager:
    push 0x3FA95770
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x13228123
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x654DE663
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0x5CB05938
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0x8921AEB3
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0xF851EEF5
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x5AD26767
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x463B0BF0
    call _WhisperMain

_NtRenameKey:
    push 0x97CCA460
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x3E262CA6
    call _WhisperMain

_NtReplaceKey:
    push 0x89D2BE63
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0x16AB3E30
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0xA435ABAE
    call _WhisperMain

_NtRequestPort:
    push 0x22B258BC
    call _WhisperMain

_NtResetEvent:
    push 0x8ED58946
    call _WhisperMain

_NtResetWriteWatch:
    push 0x3CA8464A
    call _WhisperMain

_NtRestoreKey:
    push 0x7BBE9BD5
    call _WhisperMain

_NtResumeProcess:
    push 0x4FA5483E
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0x0E90CCC3
    call _WhisperMain

_NtRollbackComplete:
    push 0x2F540BD4
    call _WhisperMain

_NtRollbackEnlistment:
    push 0xB7ABB221
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0xC8922E02
    call _WhisperMain

_NtRollbackTransaction:
    push 0x004BC61B
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0xAE329C8F
    call _WhisperMain

_NtSaveKey:
    push 0xAB989C26
    call _WhisperMain

_NtSaveKeyEx:
    push 0xB5B9FD78
    call _WhisperMain

_NtSaveMergedKeys:
    push 0xEE55F9DF
    call _WhisperMain

_NtSecureConnectPort:
    push 0xE90CE293
    call _WhisperMain

_NtSerializeBoot:
    push 0x70206AAF
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0x3F5CAD71
    call _WhisperMain

_NtSetBootOptions:
    push 0x9D89D750
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0x0AC0285E
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x54CADE0E
    call _WhisperMain

_NtSetContextThread:
    push 0x08A87A01
    call _WhisperMain

_NtSetDebugFilterState:
    push 0x3E1DEF21
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0x5CCE5960
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x519A6FCB
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0x189A0A27
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0x07A83CE5
    call _WhisperMain

_NtSetEaFile:
    push 0xA2FA64A6
    call _WhisperMain

_NtSetHighEventPair:
    push 0x24B00C05
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0x23B13A26
    call _WhisperMain

_NtSetIRTimer:
    push 0x21A23322
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0xEE33E6AF
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0x07A81C3F
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x14B80615
    call _WhisperMain

_NtSetInformationKey:
    push 0x3CD83F43
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0x95A364A7
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0xD847D6D6
    call _WhisperMain

_NtSetInformationToken:
    push 0x1E50914E
    call _WhisperMain

_NtSetInformationTransaction:
    push 0xC996C938
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x4FD34148
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x3BAB373F
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x88179E7A
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x2DB9D43D
    call _WhisperMain

_NtSetIoCompletion:
    push 0x9AD0BA05
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0xD6D4048E
    call _WhisperMain

_NtSetLdtEntries:
    push 0xEC8E3621
    call _WhisperMain

_NtSetLowEventPair:
    push 0x82D18A4A
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0x10B43029
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0x8536CBE3
    call _WhisperMain

_NtSetSecurityObject:
    push 0x0D1F6986
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0xB8DE9D5E
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0xBF81FD54
    call _WhisperMain

_NtSetSystemInformation:
    push 0x2441D522
    call _WhisperMain

_NtSetSystemPowerState:
    push 0x708386CA
    call _WhisperMain

_NtSetSystemTime:
    push 0xB435FFE3
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0xEE4DC8C4
    call _WhisperMain

_NtSetTimer2:
    push 0x57D4F08D
    call _WhisperMain

_NtSetTimerEx:
    push 0x0E84D426
    call _WhisperMain

_NtSetTimerResolution:
    push 0x0E902FDF
    call _WhisperMain

_NtSetUuidSeed:
    push 0x4862C14F
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0xB238260E
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x9012F98E
    call _WhisperMain

_NtShutdownSystem:
    push 0x0E5DD1ED
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0x4494762C
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0x253F2DA2
    call _WhisperMain

_NtSinglePhaseReject:
    push 0x16BD2E11
    call _WhisperMain

_NtStartProfile:
    push 0xEFB9C72C
    call _WhisperMain

_NtStopProfile:
    push 0xCB9B003D
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x82C35F7B
    call _WhisperMain

_NtSuspendProcess:
    push 0x1DA1042C
    call _WhisperMain

_NtSuspendThread:
    push 0x2C9F220D
    call _WhisperMain

_NtSystemDebugControl:
    push 0x876885FD
    call _WhisperMain

_NtTerminateEnclave:
    push 0xBA2998A0
    call _WhisperMain

_NtTerminateJobObject:
    push 0x20780925
    call _WhisperMain

_NtTestAlert:
    push 0x8C27A582
    call _WhisperMain

_NtThawRegistry:
    push 0x1083180D
    call _WhisperMain

_NtThawTransactions:
    push 0x3BEF7F25
    call _WhisperMain

_NtTraceControl:
    push 0xDC8ED816
    call _WhisperMain

_NtTranslateFilePath:
    push 0x8798B016
    call _WhisperMain

_NtUmsThreadYield:
    push 0xE7B8EC1E
    call _WhisperMain

_NtUnloadDriver:
    push 0xEAC7F36C
    call _WhisperMain

_NtUnloadKey:
    push 0x1DCDFFB6
    call _WhisperMain

_NtUnloadKey2:
    push 0xABD0440D
    call _WhisperMain

_NtUnloadKeyEx:
    push 0xF4783506
    call _WhisperMain

_NtUnlockFile:
    push 0xA13C9DBD
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0x73E2677D
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0xD28901D3
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0x36A710FA
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0x62BD8CF0
    call _WhisperMain

_NtVdmControl:
    push 0xDD8CF356
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x8C505AEA
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0x715A42FC
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0x48CB4B5C
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0xE28E1BFF
    call _WhisperMain

_NtWaitHighEventPair:
    push 0x10983409
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x2F01AD16
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x2893B1BA
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0x8D13A98C
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0xC51B81C8
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0x8873BAD7
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0x1AB33C23
    call _WhisperMain

_NtSavepointTransaction:
    push 0xE670989D
    call _WhisperMain

_NtSavepointComplete:
    push 0x04C92202
    call _WhisperMain

_NtCreateSectionEx:
    push 0x0096F5EB
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0x3EBB5968
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0x10C83D68
    call _WhisperMain

_NtListTransactions:
    push 0x5BC73D13
    call _WhisperMain

_NtMarshallTransaction:
    push 0x014A2217
    call _WhisperMain

_NtPullTransaction:
    push 0xF7AFD1E7
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x7AAD7A3A
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x39A9FAFF
    call _WhisperMain

_NtStartTm:
    push 0x21AC7B02
    call _WhisperMain

_NtSetInformationProcess:
    push 0x8A2A95BB
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x9B389FAC
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x02B66946
    call _WhisperMain

_NtQuerySystemTime:
    push 0xB52F9EBE
    call _WhisperMain

_NtManageHotPatch:
    push 0x7E423460
    call _WhisperMain

_NtContinueEx:
    push 0x138F4354
    call _WhisperMain

