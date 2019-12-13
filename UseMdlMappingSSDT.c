#include <ntddk.h>
#include "datatype.h"
#include "dbgmsg.h"
#include "ctrlcode.h"
#include "device.h"

#define ETHREAD_OFFSET_SERVICE_TABLE				0xbc
//使用 build  /D /g /b /B /e /F /S /s /$ /why /v /w /y  命令编译该驱动源文件
//可以查找并学习 WRK 源码中所有对 Mdl  API 相关的正确用法

/*
MDL 结构定义在 WRK 源码的 ntosdef.h 头文件中

Define a Memory Descriptor List (MDL)

An MDL describes pages in a virtual buffer in terms of physical pages.  The
pages associated with the buffer are described in an array that is allocated
just after the MDL header structure itself.

One simply calculates the base of the array by adding one to the base
MDL pointer:

    Pages = (PPFN_NUMBER) (Mdl + 1);

Notice that while in the context of the subject thread, the base virtual
address of a buffer mapped by an MDL may be referenced using the following:

    Mdl->StartVa | Mdl->ByteOffset
   */

PMDL  mdl_ptr;

//MmProbeAndLockPages() 在返回前会把传给它的 MDL 指针设定成 NULL，所以在调用它前进行备份！
PMDL  backup_mdl_ptr;

// 一枚指针，用来存储一段虚拟地址，该地址处的内容是 PFN_NUMBER（紧跟在 MDL 结构后面的物理页框号）
PPFN_NUMBER  pfn_array_follow_mdl;

short  mdl_header_length = sizeof(MDL);

DWORD*  mapped_ki_service_table;

/* os_SSDT_ptr 其实就是 KTHREAD 结构的 ServiceTable 字段，它指向 SSDT 的地址（存储在全局变量 os_SSDT 中）；
，要获得 SSDT 的地址，在 kd.exe 中以命令 dd 转储 os_SSDT_ptr，其内容应该就是 SSDT 
的地址，它与 dt nt!*DescriptorTable* -v 命令输出的第一项地址匹配，如果再以命令 dd 转储 SSDT，则得到
系统服务表的地址（存储在全局变量 os_ki_service_table 中），它与内核变量 KiServiceTable 的值相同；再以 dd/dps 转储
KiServiceTable/os_ki_service_table，则得到表中的系统服务例程的地址/函数名；

kd.exe 输出
SSDT_ptr（KTHREAD.ServiceTable 成员地址）：0x
SSDT：0x
KiServiceTable：0x

驱动打印输出
os_SSDT_ptr：0x （驱动内运行的当前线程的 KTHREAD.ServiceTable 成员地址，同样指向 ）
os_SSDT：0x
mapped_addr（Mdl 把 os_SSDT_ptr 映射到的地址）：
os_ki_service_table：

通过 kd.exe 的内核地址扩展指令 !cmkd.kvas 分析得知，KTHREAD.ServiceTable 成员位于不可换页池；
系统服务描述符表（SSDT），以及系统服务例程指针表（即 KiServiceTable）位于 BootLoaded 类型的内核空间（对应的枚举类型为 
MiVaBootLoaded）在系统初始化阶段，当控制权转交内核时，它会把 winload.exe 映射到此类内核空间，
至于为何要在此类内核空间中构建 SSDT 和 KiServiceTable，其意图尚待分析

MDL 把 KTHREAD.ServiceTable 成员（指向 SSDT）映射到的内核空间属于 SystemPte，即系统页表条目，此类内核空间有多种用途，
包括提供给 MDL 来把 SSDT/KiServiceTable 映射到此处。
系统页表条目（PTEs）内核空间，用于动态地映射系统页面，例如 I/O 空间，内核栈，以及映射内存描述符列表（MDLs）。
系统 PTE 的分配者除了各种执行体/内核组件外，多数是一些加载到内核空间的设备驱动程序，其中有系统自带的，也有第三方软硬件供应商开发的；
它们请求在系统 PTE 区域中分配内存的目的都是与映射视图，MDLs（内存描述符列表），适配器内存映射，驱动程序映像，
内核栈， I/O 映射等相关的。
例如，MiFindContiguousMemory() -> MmMapIoSpace() -> MiInsertIoSpaceMap -> ExAllocatePoolWithTag() -> 
MiAllocatePoolPages() -> MiAllocatePagedPoolPages() -> MiObtainSystemVa()
由此可知，无论是直接还是间接调用 MiObtainSystemVa() ，来在系统 PTE 区域分配内存，都会被跟踪记录下来
（启用系统 PTE 分配者跟踪后）。



*/

void**  os_SSDT_ptr;
//PVOID  os_SSDT_ptr;

 DWORD*  os_SSDT;
 //DWORD  os_SSDT;

 DWORD  os_ki_service_table;


 typedef NTSTATUS(*OriginalSystemServicePtr)
(
	HANDLE PortHandle
);

 OriginalSystemServicePtr  ori_sys_service_ptr;


 NTSTATUS our_hooking_routine(HANDLE PortHandle) 
 {
		
	 return (ori_sys_service_ptr(PortHandle));
 
 }


PVOID  MapMdl(PMDL  mdl_pointer, PVOID  VirtualAddress, ULONG  Length);
void  UnMapMdl(PMDL  mdl_pointer, PVOID  baseaddr);

//动态卸载后，dps 转储 mapped_ki_service_table 变量的输出应该不是系统服务例程了 
VOID Unload(PDRIVER_OBJECT driver)
{

	DBG_TRACE("OnUnload", "卸载前首先取消 MDL 对 KiServiceTable 的映射");
	UnMapMdl(mdl_ptr, mapped_ki_service_table);
	DBG_TRACE("OnUnload",  "UseMdlMappingSSDT.sys 已卸载");
	return;

}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	BYTE*   currentETHREADpointer = NULL;
	

	driver->DriverUnload = Unload;
	currentETHREADpointer = (UCHAR*)PsGetCurrentThread();

	 os_SSDT_ptr = (void**)(currentETHREADpointer + ETHREAD_OFFSET_SERVICE_TABLE);
	 // os_SSDT_ptr = (void*)(currentETHREADpointer + ETHREAD_OFFSET_SERVICE_TABLE);

	 os_SSDT = *(DWORD**)os_SSDT_ptr;
	 // os_SSDT = *(DWORD*)os_SSDT_ptr;

	os_ki_service_table = *(DWORD*)os_SSDT;

	//这段调用会导致 bugcheck code 为 0x000000BE，亦即尝试向只读的内核地址写入，因为原始的 KiServiceTable 就是只读的
	//RtlFillMemory((DWORD*)os_ki_service_table, 0x4, (UCHAR)'A');

	//下面调用的第二个参数，根据前面获取到的是 SSDT 指针，SSDT，还是 KiServiceTable，来传入相应的实参
	// 此处把 KiServiceTable，以及系统服务指针表，由 os_ki_service_table 变量保存，映射到另一个内核地址处
	mapped_ki_service_table = MapMdl(mdl_ptr, (PVOID)os_ki_service_table,  0x191 * 4);

	if (mapped_ki_service_table == NULL) {

		DBG_TRACE("Driver Entry", ".........无法分配 MDL 来描述 OS 的 SSDT，并把它映射到另一个内核地址对其挂钩和修改.......");
	}

	
	DbgPrint("我们把原始的 OS 系统服务指针表以写权限映射到的新内核空间为:   %p\r\n", mapped_ki_service_table);
	DbgPrint("解引这个新内核地址，应该就是表中的第一个系统服务的地址，或者用调试器命令 !dps 检查两者是否为同一张调用表:   %p\r\n", *mapped_ki_service_table);

		
//0x39 号系统服务为 nt!NtCompleteConnectPort() ，因为它只有一个参数，而且是文档化的，所以较易 hook 并重定向

	ori_sys_service_ptr = mapped_ki_service_table[0x39];

	mapped_ki_service_table[0x39] = our_hooking_routine;

	DbgPrint("我们把 0x39 号系统服务挂钩为:   %p\r\n", mapped_ki_service_table[0x39]);

	/*
	//RtlFillMemory(mapped_ki_service_table, 0x4, (UCHAR)'S');
	//DbgPrint("利用 RtlFillMemory() 把第一个系统服务函数的地址填充为全“Z”:   %p\r\n", *mapped_ki_service_table);
	*/


	return STATUS_SUCCESS;
}



PVOID  MapMdl(PMDL  mdl_pointer,  PVOID  VirtualAddress,  ULONG  Length) {

		PVOID  mapped_addr;
		//PVOID  mapped_addr2;
		// PVOID  mapped_addr3;

		// 打印 os_SSDT_ptr 本身（KHTREAD 的 ServiceTable 字段）的地址
		DbgPrint(" _KTHREAD.ServiceTable 自身的地址:   %p\r\n", &os_SSDT_ptr);
		DbgPrint(" ServiceTable 指向:   %p\r\n", os_SSDT_ptr);
		DbgPrint(" ServiceTable 所指处的内容:   %p\r\n", *os_SSDT_ptr);
		DbgPrint(" SSDT，亦即 nt!KeServiceDescriptorTable 地址，与 ServiceTable 所指处内容一致: %p\r\n", os_SSDT);

	// 打印系统服务例程指针表的地址，可以通过 MDL + MmProbeAndLockPages()，把系统服务例程指针表以可写的形式映射到
	//SystemPTE 类型的内核空间，然后尝试对映射到的地址执行 RtlZeroMemory() 之类的操作，看是否会改变原始的 KiServiceTable 。
	// 还可以用 !pte 命令来证实 MDL + MmProbeAndLockPages() 映射到的虚拟地址对应的物理页为可写
	// 注意，应该对 KiServiceTable 证实，因为 SSDT 的原始状态就是可写的
		DbgPrint(" nt!KeServiceDescriptorTable 所指处的内容:   %X\r\n", *os_SSDT);
		DbgPrint(" KiServiceTable 地址，与上面一致:   %X\r\n", os_ki_service_table);
		DBG_TRACE("MapMdl", ".......表中的系统服务地址可以通过 dps 转储 os_ki_service_table 查看！..........r\n");

	// 如果能确定要映射的缓冲区在非换页池中，就无需调用后面的 MmProbeAndLockPages()，也就用不上 try......except 逻辑块

		try {

			mdl_pointer = IoAllocateMdl(VirtualAddress, 0x191 * 4, FALSE, FALSE, NULL);

			if (mdl_pointer == NULL) {

				DBG_TRACE("MapMdl", ".........无法分配一个 MDL 来描述原始的 KiServiceTable ！..........\r\n");
				return  NULL;
			}

			DbgPrint("分配的 MDL 指针自身的地址:  %p ，可用 dd 转储它持有的地址\r\n", &mdl_pointer);
			DbgPrint("分配的 MDL 指针指向一个 _MDL 的地址:   %p，与 dd %p 的输出一致，它用来描述原始的 KiServiceTable\r\n", mdl_pointer, &mdl_pointer);

			//把分配的 MDL 指针备份起来，因为 MmGetSystemAddressForMdlSafe() 调用会把传给它的 MDL 指针指向其它系统数据
			backup_mdl_ptr = mdl_pointer;

			// 这里设置的两个断点是为了观察调用前后的 _MDL.MdlFlags 如何变化
			__asm { 

				int 3;
			}

			if (mdl_pointer->MdlFlags & MDL_ALLOCATED_FIXED_SIZE)
			{
				DBG_TRACE("MapMdl", ".....IoAllocateMdl() 分配的 MDL 结构有固定大小（MDL_ALLOCATED_FIXED_SIZE）........\r\n");
			}

			MmProbeAndLockPages(mdl_pointer, KernelMode, IoWriteAccess);

			__asm {

				int 3;
			}

			if ((mdl_pointer->MdlFlags & MDL_ALLOCATED_FIXED_SIZE) &&
				(mdl_pointer->MdlFlags & MDL_WRITE_OPERATION) &&
				(mdl_pointer->MdlFlags & MDL_PAGES_LOCKED))
			{
				DBG_TRACE("MapMdl", " MmProbeAndLockPages() 以写权限（MDL_WRITE_OPERATION）把 MDL 描述的原始 KiServiceTable 所在页面锁定到物理内存中（MDL_PAGES_LOCKED）\r\n");
			}
			
			/*前后分别设置一个断点，验证 MmGetSystemAddressForMdlSafe() 是否把 MDL 释放了。。。。
			经验证，MmGetSystemAddressForMdlSafe() 会把 MDL 指向其它系统数据，而非释放它指向的 _MDL 结构，因此 MmGetSystemAddressForMdlSafe()
			调用后无法依靠检查 MDL 指针是否为空来断言 _MDL 结构是否被释放*/

			mapped_addr = MmGetSystemAddressForMdlSafe(mdl_pointer, NormalPagePriority);

			// 此处顺便观察 _MDL.MdlFlags 的变化
			__asm {

				int 3;
			}

			if (
				(mdl_pointer->MdlFlags & MDL_ALLOCATED_FIXED_SIZE) &&
				(mdl_pointer->MdlFlags & MDL_WRITE_OPERATION) &&
				(mdl_pointer->MdlFlags & MDL_PAGES_LOCKED) &&
				(mdl_pointer->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
				)
			{
				DBG_TRACE("MapMdl", " MmGetSystemAddressForMdlSafe() 把 MDL 结构描述的原始 KiServiceTable 映射到另一个内核虚拟地址（MDL_MAPPED_TO_SYSTEM_VA）\r\n");
			}


			DbgPrint("MmGetSystemAddressForMdlSafe() 调用依然可以通过原始的 MDL 指针访问 _MDL 的地址:   %p\r\n", mdl_pointer);
			DbgPrint("也可以通过备份的 MDL 指针访问 _MDL 的地址:   %p，这都说明 MDL 结构尚未被释放，\r\n", backup_mdl_ptr);

			
			pfn_array_follow_mdl = (PPFN_NUMBER)(mdl_pointer + 1);

			
			DbgPrint(" MDL 结构后偏移 %2x 地址处是一个 PFN 数组，用来存储该 MDL 描述的虚拟缓冲区映射到的物理页框号\r\n", mdl_header_length);
			DbgPrint(" 该 PFN 数组的起始地址为：%p\r\n", pfn_array_follow_mdl);
			DbgPrint(" 第一个物理页框号为：%p\r\n", *pfn_array_follow_mdl);
			

				/*打印前面调用返回的地址，它输出 Mdl 把原始的 os_SSDT_ptr 映射到的另一个内核地址；尽管如此，
				在 kd.exe 中转储 os_SSDT_ptr 与 mapped_addr，应该得出相同的内容，表明它们都指向 SSDT。
注意，MmProbeAndLockPages() 调用会假设 mdl 描述的缓冲区在可换页池中，并且将其锁定，前面说过，
 IoAllocateMdl() 不会初始化 MDL 后面的 PFN 数组，假设直接按照 IoAllocateMdl() -> MmGetSystemAddressForMdlSafe()
 然后打印，其 os_SSDT_ptr 映射到的地址是错误的，kd.exe 无法转储验证；因此需要执行下面其中之一的正确步骤：
1 。 IoAllocateMdl() -> MmProbeAndLockPages() -> MmGetSystemAddressForMdlSafe() ， os_SSDT_ptr 被映射到另一个
 内核地址（mapped_addr 不等于 os_SSDT_ptr），但同样指向 SSDT

2。 IoAllocateMdl() -> MmBuildMdlForNonPagedPool() -> MmGetSystemAddressForMdlSafe()，因为
MmBuildMdlForNonPagedPool() 假设 Mdl 描述的 os_SSDT_ptr 已经在不可换页池中，它不会创建额外的内核地址映射，
 因此 mapped_addr2 就等于 os_SSDT_ptr

			根据前面为 MapMdl() 的第二个参数传入的实参，换成不同的打印信息
			DbgPrint("the MmGetSystemAddressForMdlSafe() mapping OS SSDT pointer to :   %p",  mapped_addr);

	MmBuildMdlForNonPagedPool() 与 MmProbeAndLockPages()，MmMapLockedPagesSpecifyCache() 
		不可同时使用；MmBuildMdlForNonPagedPool()
		的参数 mdl 必须是 IoAllocateMdl() 创建的，描述不可换页池的 mdl，在此场景中，mdl 描述的 ETHREAD 结构应该位于
	不可换页池中；向 MmGetSystemAddressForMdlSafe() 传入一个由 MmBuildMdlForNonPagedPool() 构建的 MDL 是允许的。
		在这种情况下，MmGetSystemAddressForMdlSafe() 调用只是返回由该 MDL 描述的缓冲区的起始虚拟地址。
				MmBuildMdlForNonPagedPool(mdl);
				mapped_addr2 = MmGetSystemAddressForMdlSafe(mdl,  NormalPagePriority);

	通过将下面的打印结果与上一个比较，可以检测 MmBuildMdlForNonPagedPool() 是否会为 os_SSDT_ptr 创建额外的映射：
	如果 mapped_addr2 与 mapped_addr 相同，则不会。
			结果是不会，MDL 描述的缓冲区的起始虚拟地址就是线程的 KTHREAD.ServiceTable 成员地址）
			DbgPrint("the MmGetSystemAddressForMdlSafe() ->MmBuildMdlForNonPagedPool()  mapping OS SSDT pointer to :   %p",  mapped_addr2);
			*/
				
			return mapped_addr;
				
				/*
				mapped_addr3 = MmMapLockedPagesSpecifyCache(mdl,
																									KernelMode,
																									MmNonCached,
																									NULL,
																									FALSE,
																									NormalPagePriority);

				DbgPrint("MmMapLockedPagesSpecifyCache() mapping the SSDT start from:   %p", mapped_addr3);
								if (mapped_addr3 == NULL) {
										DBG_TRACE("MapMdl", "..........all the way can't access mapped SSDT, give up!.........");
										MmUnlockPages(mdl);
										IoFreeMdl(mdl);
								}
								return  mapped_addr;
						}
						return  mapped_addr;
			}
		*/
		}

		except (STATUS_ACCESS_VIOLATION) {

			IoFreeMdl(mdl_pointer);
			return NULL;
		}
		
}



void  UnMapMdl(PMDL  mdl_pointer,  PVOID  baseaddr) {

	if (mdl_pointer != backup_mdl_ptr) {

		DBG_TRACE("UnMapMdl", ".......先解锁备份 MDL 映射的页面，然后释放备份的 MDL........");

		MmUnlockPages(backup_mdl_ptr);	// 此例程的效果是，无法通过映射的系统地址来访问 KiServiceTable，且 _MDL 结构中各字段已发生变化，
		IoFreeMdl(backup_mdl_ptr);		// 此例程的效果是，MDL 指针不再持有 _MDL 结构的地址


		if (backup_mdl_ptr == NULL) {

			DBG_TRACE("UnMapMdl", ".............解锁页面，释放备份 MDL 完成！................");
		}

		return;
	}


	DBG_TRACE("UnMapMdl", ".........原始 MDL 未被修改，解锁它映射的页面后释放它...........");
		
		// 如果前面使用 MmBuildMdlForNonPagedPool() ，就不能执行下面前2个操作
		//MmUnmapLockedPages(baseaddr,  mdl);
	MmUnlockPages(mdl_pointer);
	IoFreeMdl(mdl_pointer);

	if (mdl_pointer == NULL) {

		DBG_TRACE("UnMapMdl", ".............解锁页面，释放原始 MDL 完成！................");
	}

	return;
}
