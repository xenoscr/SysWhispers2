#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#define SW2_SEED 0x951B6F91
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList(void);
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, *PPS_CREATE_STATE;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, *PKEY_SET_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, *PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, *PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, *PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, *PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;
		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, *PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, *PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, *PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, *PIO_SESSION_STATE;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, *PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, *PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, *PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, *PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, *PKCONTINUE_ARGUMENT;

EXTERN_C NTSTATUS SyscallsAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus);

EXTERN_C NTSTATUS SyscallsWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS SyscallsAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL);

EXTERN_C NTSTATUS SyscallsMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS SyscallsWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS SyscallsCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status);

EXTERN_C NTSTATUS SyscallsReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS SyscallsDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS SyscallsWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS SyscallsRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS SyscallsReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage);

EXTERN_C NTSTATUS SyscallsReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS SyscallsSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

EXTERN_C NTSTATUS SyscallsSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS SyscallsClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS SyscallsQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS SyscallsOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS SyscallsFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId);

EXTERN_C NTSTATUS SyscallsQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS SyscallsQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS SyscallsAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS SyscallsQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS SyscallsFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS SyscallsImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message);

EXTERN_C NTSTATUS SyscallsReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS SyscallsRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS SyscallsQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS SyscallsQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS SyscallsMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS SyscallsAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS SyscallsUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS SyscallsReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS SyscallsSetEventBoostPriority(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS SyscallsReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS SyscallsOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS SyscallsQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

EXTERN_C NTSTATUS SyscallsEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS SyscallsOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS SyscallsDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS SyscallsQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS SyscallsQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS SyscallsWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS SyscallsCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS SyscallsDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options);

EXTERN_C NTSTATUS SyscallsQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation);

EXTERN_C NTSTATUS SyscallsClearEvent(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS SyscallsReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS SyscallsContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert);

EXTERN_C NTSTATUS SyscallsQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId);

EXTERN_C NTSTATUS SyscallsQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS SyscallsYieldExecution();

EXTERN_C NTSTATUS SyscallsAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState);

EXTERN_C NTSTATUS SyscallsQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass);

EXTERN_C NTSTATUS SyscallsCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS SyscallsFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData);

EXTERN_C NTSTATUS SyscallsCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

EXTERN_C NTSTATUS SyscallsCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended);

EXTERN_C NTSTATUS SyscallsIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL);

EXTERN_C NTSTATUS SyscallsProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS SyscallsQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS SyscallsTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS SyscallsReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength);

EXTERN_C NTSTATUS SyscallsQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS SyscallsWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength);

EXTERN_C NTSTATUS SyscallsCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields);

EXTERN_C NTSTATUS SyscallsPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS SyscallsSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize);

EXTERN_C NTSTATUS SyscallsCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL);

EXTERN_C NTSTATUS SyscallsAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS SyscallsAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS SyscallsAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS SyscallsAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS SyscallsAcquireProcessActivityReference();

EXTERN_C NTSTATUS SyscallsAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS SyscallsAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS SyscallsAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS SyscallsAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlertThread(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS SyscallsAlertThreadByThreadId(
	IN ULONG ThreadId);

EXTERN_C NTSTATUS SyscallsAllocateLocallyUniqueId(
	OUT PLUID Luid);

EXTERN_C NTSTATUS SyscallsAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type);

EXTERN_C NTSTATUS SyscallsAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray);

EXTERN_C NTSTATUS SyscallsAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed);

EXTERN_C NTSTATUS SyscallsAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS SyscallsAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection);

EXTERN_C NTSTATUS SyscallsAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext);

EXTERN_C NTSTATUS SyscallsAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize);

EXTERN_C NTSTATUS SyscallsAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId);

EXTERN_C NTSTATUS SyscallsAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes);

EXTERN_C NTSTATUS SyscallsAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute);

EXTERN_C NTSTATUS SyscallsAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle);

EXTERN_C NTSTATUS SyscallsAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId);

EXTERN_C NTSTATUS SyscallsAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase);

EXTERN_C NTSTATUS SyscallsAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS SyscallsAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags);

EXTERN_C NTSTATUS SyscallsAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS SyscallsAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS SyscallsAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile);

EXTERN_C NTSTATUS SyscallsAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS SyscallsAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL);

EXTERN_C NTSTATUS SyscallsCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL);

EXTERN_C NTSTATUS SyscallsCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters);

EXTERN_C NTSTATUS SyscallsCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket);

EXTERN_C NTSTATUS SyscallsCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS SyscallsCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS SyscallsCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray);

EXTERN_C NTSTATUS SyscallsCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle);

EXTERN_C NTSTATUS SyscallsCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2);

EXTERN_C NTSTATUS SyscallsCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal);

EXTERN_C NTSTATUS SyscallsCompleteConnectPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS SyscallsCompressKey(
	IN HANDLE Key);

EXTERN_C NTSTATUS SyscallsConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS SyscallsCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS SyscallsCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout);

EXTERN_C NTSTATUS SyscallsCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner);

EXTERN_C NTSTATUS SyscallsCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority);

EXTERN_C NTSTATUS SyscallsCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode);

EXTERN_C NTSTATUS SyscallsCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS SyscallsCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity);

EXTERN_C NTSTATUS SyscallsCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity);

EXTERN_C NTSTATUS SyscallsCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags);

EXTERN_C NTSTATUS SyscallsCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount);

EXTERN_C NTSTATUS SyscallsCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget);

EXTERN_C NTSTATUS SyscallsCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType);

EXTERN_C NTSTATUS SyscallsCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS SyscallsCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS SyscallsCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS SyscallsCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor);

EXTERN_C NTSTATUS SyscallsCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL);

EXTERN_C NTSTATUS SyscallsDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS SyscallsDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);

EXTERN_C NTSTATUS SyscallsDeleteAtom(
	IN USHORT Atom);

EXTERN_C NTSTATUS SyscallsDeleteBootEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS SyscallsDeleteDriverEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS SyscallsDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsDeleteKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS SyscallsDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS SyscallsDeletePrivateNamespace(
	IN HANDLE NamespaceHandle);

EXTERN_C NTSTATUS SyscallsDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName);

EXTERN_C NTSTATUS SyscallsDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL);

EXTERN_C NTSTATUS SyscallsDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS SyscallsDisableLastKnownGood();

EXTERN_C NTSTATUS SyscallsDisplayString(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS SyscallsDrawText(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS SyscallsEnableLastKnownGood();

EXTERN_C NTSTATUS SyscallsEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS SyscallsEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS SyscallsEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS SyscallsEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS SyscallsExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize);

EXTERN_C NTSTATUS SyscallsFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize);

EXTERN_C NTSTATUS SyscallsFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS SyscallsFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS SyscallsFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag);

EXTERN_C NTSTATUS SyscallsFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS SyscallsFlushKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS SyscallsFlushProcessWriteBuffers();

EXTERN_C NTSTATUS SyscallsFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS SyscallsFlushWriteBuffer();

EXTERN_C NTSTATUS SyscallsFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray);

EXTERN_C NTSTATUS SyscallsFreezeRegistry(
	IN ULONG TimeOutInSeconds);

EXTERN_C NTSTATUS SyscallsFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout);

EXTERN_C NTSTATUS SyscallsGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL);

EXTERN_C NTSTATUS SyscallsGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize);

EXTERN_C NTSTATUS SyscallsGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS SyscallsGetCurrentProcessorNumber();

EXTERN_C NTSTATUS SyscallsGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL);

EXTERN_C NTSTATUS SyscallsGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State);

EXTERN_C NTSTATUS SyscallsGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData);

EXTERN_C NTSTATUS SyscallsGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle);

EXTERN_C NTSTATUS SyscallsGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle);

EXTERN_C NTSTATUS SyscallsGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize);

EXTERN_C NTSTATUS SyscallsGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL);

EXTERN_C NTSTATUS SyscallsGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity);

EXTERN_C NTSTATUS SyscallsImpersonateAnonymousToken(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS SyscallsImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos);

EXTERN_C NTSTATUS SyscallsInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS SyscallsInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize);

EXTERN_C NTSTATUS SyscallsInitializeRegistry(
	IN USHORT BootCondition);

EXTERN_C NTSTATUS SyscallsInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS SyscallsIsSystemResumeAutomatic();

EXTERN_C NTSTATUS SyscallsIsUILanguageComitted();

EXTERN_C NTSTATUS SyscallsListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest);

EXTERN_C NTSTATUS SyscallsLoadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS SyscallsLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS SyscallsLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag);

EXTERN_C NTSTATUS SyscallsLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile);

EXTERN_C NTSTATUS SyscallsLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL);

EXTERN_C NTSTATUS SyscallsLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock);

EXTERN_C NTSTATUS SyscallsLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL);

EXTERN_C NTSTATUS SyscallsLockRegistryKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS SyscallsLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType);

EXTERN_C NTSTATUS SyscallsMakePermanentObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS SyscallsMakeTemporaryObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS SyscallsManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength);

EXTERN_C NTSTATUS SyscallsMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL);

EXTERN_C NTSTATUS SyscallsMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS SyscallsMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS SyscallsModifyBootEntry(
	IN PBOOT_ENTRY BootEntry);

EXTERN_C NTSTATUS SyscallsModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry);

EXTERN_C NTSTATUS SyscallsNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree);

EXTERN_C NTSTATUS SyscallsNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL);

EXTERN_C NTSTATUS SyscallsNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS SyscallsNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS SyscallsNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize);

EXTERN_C NTSTATUS SyscallsOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS SyscallsOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS SyscallsOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS SyscallsOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS SyscallsOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS SyscallsOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS SyscallsOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS SyscallsOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL);

EXTERN_C NTSTATUS SyscallsOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL);

EXTERN_C NTSTATUS SyscallsPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength);

EXTERN_C NTSTATUS SyscallsPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result);

EXTERN_C NTSTATUS SyscallsPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS SyscallsPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS SyscallsPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer);

EXTERN_C NTSTATUS SyscallsPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus);

EXTERN_C NTSTATUS SyscallsPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency);

EXTERN_C NTSTATUS SyscallsQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS SyscallsQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength);

EXTERN_C NTSTATUS SyscallsQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level);

EXTERN_C NTSTATUS SyscallsQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS SyscallsQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS SyscallsQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation);

EXTERN_C NTSTATUS SyscallsQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS SyscallsQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId);

EXTERN_C NTSTATUS SyscallsQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval);

EXTERN_C NTSTATUS SyscallsQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize);

EXTERN_C NTSTATUS SyscallsQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount);

EXTERN_C NTSTATUS SyscallsQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize);

EXTERN_C NTSTATUS SyscallsQueryPortInformationProcess();

EXTERN_C NTSTATUS SyscallsQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS SyscallsQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS SyscallsQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded);

EXTERN_C NTSTATUS SyscallsQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6);

EXTERN_C NTSTATUS SyscallsQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL);

EXTERN_C NTSTATUS SyscallsQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime);

EXTERN_C NTSTATUS SyscallsQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize);

EXTERN_C NTSTATUS SyscallsQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize);

EXTERN_C NTSTATUS SyscallsQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS SyscallsRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance);

EXTERN_C NTSTATUS SyscallsRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response);

EXTERN_C NTSTATUS SyscallsReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS SyscallsRecoverResourceManager(
	IN HANDLE ResourceManagerHandle);

EXTERN_C NTSTATUS SyscallsRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle);

EXTERN_C NTSTATUS SyscallsRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL);

EXTERN_C NTSTATUS SyscallsRegisterThreadTerminatePort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS SyscallsReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS SyscallsRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable);

EXTERN_C NTSTATUS SyscallsRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS SyscallsRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName);

EXTERN_C NTSTATUS SyscallsRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid);

EXTERN_C NTSTATUS SyscallsReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile);

EXTERN_C NTSTATUS SyscallsReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS SyscallsRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage);

EXTERN_C NTSTATUS SyscallsResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS SyscallsResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize);

EXTERN_C NTSTATUS SyscallsRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS SyscallsRevertContainerImpersonation();

EXTERN_C NTSTATUS SyscallsRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS SyscallsRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS SyscallsRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS SyscallsSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format);

EXTERN_C NTSTATUS SyscallsSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS SyscallsSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsSerializeBoot();

EXTERN_C NTSTATUS SyscallsSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count);

EXTERN_C NTSTATUS SyscallsSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange);

EXTERN_C NTSTATUS SyscallsSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS SyscallsSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State);

EXTERN_C NTSTATUS SyscallsSetDefaultHardErrorPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS SyscallsSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId);

EXTERN_C NTSTATUS SyscallsSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId);

EXTERN_C NTSTATUS SyscallsSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count);

EXTERN_C NTSTATUS SyscallsSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize);

EXTERN_C NTSTATUS SyscallsSetHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS SyscallsSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS SyscallsSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength);

EXTERN_C NTSTATUS SyscallsSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength);

EXTERN_C NTSTATUS SyscallsSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength);

EXTERN_C NTSTATUS SyscallsSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source);

EXTERN_C NTSTATUS SyscallsSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered);

EXTERN_C NTSTATUS SyscallsSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation);

EXTERN_C NTSTATUS SyscallsSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi);

EXTERN_C NTSTATUS SyscallsSetLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS SyscallsSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS SyscallsSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length);

EXTERN_C NTSTATUS SyscallsSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer);

EXTERN_C NTSTATUS SyscallsSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value);

EXTERN_C NTSTATUS SyscallsSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes);

EXTERN_C NTSTATUS SyscallsSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength);

EXTERN_C NTSTATUS SyscallsSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL);

EXTERN_C NTSTATUS SyscallsSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState);

EXTERN_C NTSTATUS SyscallsSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters);

EXTERN_C NTSTATUS SyscallsSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength);

EXTERN_C NTSTATUS SyscallsSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution);

EXTERN_C NTSTATUS SyscallsSetUuidSeed(
	IN PUCHAR Seed);

EXTERN_C NTSTATUS SyscallsSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass);

EXTERN_C NTSTATUS SyscallsSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent);

EXTERN_C NTSTATUS SyscallsShutdownSystem(
	IN SHUTDOWN_ACTION Action);

EXTERN_C NTSTATUS SyscallsShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount);

EXTERN_C NTSTATUS SyscallsSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL);

EXTERN_C NTSTATUS SyscallsSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsStartProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS SyscallsStopProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS SyscallsSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL);

EXTERN_C NTSTATUS SyscallsSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS SyscallsSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS SyscallsSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread);

EXTERN_C NTSTATUS SyscallsTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS SyscallsTestAlert();

EXTERN_C NTSTATUS SyscallsThawRegistry();

EXTERN_C NTSTATUS SyscallsThawTransactions();

EXTERN_C NTSTATUS SyscallsTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS SyscallsTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL);

EXTERN_C NTSTATUS SyscallsUmsThreadYield(
	IN PVOID SchedulerParam);

EXTERN_C NTSTATUS SyscallsUnloadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS SyscallsUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName);

EXTERN_C NTSTATUS SyscallsUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL);

EXTERN_C NTSTATUS SyscallsUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key);

EXTERN_C NTSTATUS SyscallsUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN PSIZE_T NumberOfBytesToUnlock,
	IN ULONG LockType);

EXTERN_C NTSTATUS SyscallsUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS SyscallsUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS SyscallsUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp);

EXTERN_C NTSTATUS SyscallsVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData);

EXTERN_C NTSTATUS SyscallsWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange);

EXTERN_C NTSTATUS SyscallsWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS SyscallsWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket);

EXTERN_C NTSTATUS SyscallsWaitHighEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS SyscallsWaitLowEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS SyscallsAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting);

EXTERN_C NTSTATUS SyscallsCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS SyscallsClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS SyscallsClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS SyscallsRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS SyscallsSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId);

EXTERN_C NTSTATUS SyscallsSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS SyscallsCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount);

EXTERN_C NTSTATUS SyscallsCreateCrossVmEvent();

EXTERN_C NTSTATUS SyscallsGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize);

EXTERN_C NTSTATUS SyscallsListTransactions();

EXTERN_C NTSTATUS SyscallsMarshallTransaction();

EXTERN_C NTSTATUS SyscallsPullTransaction();

EXTERN_C NTSTATUS SyscallsReleaseCMFViewOwnership();

EXTERN_C NTSTATUS SyscallsWaitForWnfNotifications();

EXTERN_C NTSTATUS SyscallsStartTm();

EXTERN_C NTSTATUS SyscallsSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length);

EXTERN_C NTSTATUS SyscallsRequestDeviceWakeup(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS SyscallsRequestWakeupLatency(
	IN ULONG LatencyTime);

EXTERN_C NTSTATUS SyscallsQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime);

EXTERN_C NTSTATUS SyscallsManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS SyscallsContinueEx(
	IN PCONTEXT ContextRecord,
	IN PKCONTINUE_ARGUMENT ContinueArgument);

#endif
