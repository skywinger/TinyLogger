// ProtoMsgTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "windows.h"
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include "tlog.h"

using namespace tlog;

typedef void(__stdcall* FUNC_SETOBJ)(void*);

std::atomic_bool g_atoStart;

void logThread()
{
	while (!g_atoStart.load());

	std::cout << "write log start!" << std::endl;

	for (int i = 0; i < 100000; ++i)
	{
		LOG_CRIT("multi thread log test. a looooooooooooooooooooooooooooooooooooooooooooooooooooooooog string, i value is %d!", i);
	}
}

int main()
{
	std::string logFullPath = ".\\logs";
	//Logger::initLogger("SysMonitor", true, Priority::INFO, 4096, logFullPath, 2 * 1000 * 1024);
	//Logger::initLogger("SysMonitor", true, Priority::HEX, 512, logFullPath, 8 * 1000 * 1024);
	//Logger::initLogger("SysMonitor", true, Priority::NOTSET, 4096, logFullPath, 2 * 1000 * 1024);
	//Logger::initLogger("SysMonitor", true, Priority::ERROR, 4096, logFullPath, 2 * 1000 * 1024);
	//Logger::initLogger("SysMonitor", true, Priority::WARN, 4096, logFullPath, 2 * 1000 * 1024);
	Logger::initLogger("SysMonitor", false, Priority::CRIT, 512, logFullPath, 8 * 1024 * 1024);
	//Logger::initLogger("SysMonitor", true, Priority::DEBUG, 4096, logFullPath, 8 * 1000 * 1024);

#if 0
	LOG_INFO("Start SysMonitor Service ...");
	LOG_FATAL("系统调用出错!");
	LOG_PAUSE("Press any key to continue ...");
	LOG_CRIT("Current Path : %s", logFullPath);

	HMODULE dllmod;
	std::string dllname = ".\\TestDll.dll";
	dllmod = LoadLibraryA(dllname.c_str());
	if (dllmod == nullptr)
	{
		LOG_ERROR("找不到名称为[%s]的动态库，请检查配置是否正确", dllname.c_str());
		Logger::lazyDownLogger();
		return 1;
	}
	LOG_CRIT("加载动态库[ %s ]成功", dllname.c_str());

	LOG_CRIT("从动态库获取getANum方法");
	FARPROC m_func = GetProcAddress(dllmod, "getANum");
	if (m_func)
	{
		int num = 0;
		num = static_cast<int>(m_func());
		if (num != 0)
		{
			LOG_CRIT("调用getANum方法, 返回: [ %d ]", num);
		}
	}

	LOG_CRIT("从动态库获取setTestObj方法");
	FUNC_SETOBJ m_func1 = (FUNC_SETOBJ)GetProcAddress(dllmod, "setTestObj");
	if (m_func1)
	{
		std::string* str = new std::string("hello world");
		LOG_CRIT("执行函数setTestObj ...");
		m_func1(str);
		LOG_CRIT("执行函数setTestObj成功");
		delete str;
	}

	std::string hexstr = "\x21\x08\x20\x0d该文件包含不能在当前代码页(936)中表示的字符。请将该文件保存为 Unicode 格式以防止数据丢失\x24\x84";
	HEX_DUMP("调试信息", (byte*)hexstr.c_str(), hexstr.length());
	LOG_TRACE("hi girl");
	LOG_WARN("警告: '请按提示操作'");
	LOG_DEBUG("=================================================================");
	LOG_ERROR("出错啦!!! ~~~~~ ,,,,");
	LOG_PAUSE("请按任意键继续...");
#endif

//#if 0
	std::cout << "log write test,log size about 64～69 MB every time..." << std::endl;
	//单线程写日志
	{
		std::cout << "single thread log test..." << std::endl;
		TimeCounter timeCouner;
		for (int i = 0; i < 400000; ++i)
		{
			LOG_CRIT("single thread log test. a looooooooooooooooooooooooooooooooooooooooooooooooooooooooog string, i value is %d!", i);
			//std::cout << "i value is" << i << std::endl;
			//std::this_thread::sleep_for(std::chrono::microseconds(10));
		}
		std::cout << "\nsingle thread write log 64～69MB time cost " << timeCouner.format_thousands(timeCouner.elapsed_milli(), ',') << " ms" << std::endl;
	}

	system("pause");

//#endif
	
//#if 0
	//多线程写日志
	{
		std::cout << "multi thread log test..." << std::endl;
		g_atoStart.store(false);
		std::vector<std::thread> vecThread;
		for (int i = 0; i < 4; ++i)
		{
			vecThread.emplace_back(std::thread(logThread));
		}
		g_atoStart.store(true);
		TimeCounter timeCouner;
		for (auto& iterThread : vecThread)
		{
			iterThread.join();
		}
		std::cout << "\nmulti thread write log 64～69MB time cost " << timeCouner.format_thousands(timeCouner.elapsed_milli(), ',') << " ms" << std::endl;
	}

	system("pause");
//#endif

	Logger::lazyDownLogger();

	return 0;
}
