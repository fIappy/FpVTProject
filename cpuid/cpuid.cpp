// cpuid.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <intrin.h>
void _sgdt(void*);
int main()
{

	int info[4] = { 0 };
	__cpuid(info, 1);
	info[0] = _mm_crc32_u32(0xffffffff, 0x11223344);
//	__cpuid(info, 0x80000008);//0x00003027 
//	__cpuid(info, 0x80000001);//0x00003027 
//	
////	uint64_t a= __readmsr(0x176);
//	uint64_t b[2] = { 0 };
//	_sgdt(b);
	//__asm
	//{
	//	xor eax,eax
	//	bt al,1
	//	jb aaaa
	//	xor eax,eax

	//aaaa:
	//	xor ebx,ebx
	//}
	
    std::cout << "Hello World!\n"; 
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
