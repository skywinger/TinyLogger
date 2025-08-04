// Created by skywinger on 2023-11-02.
#ifndef __TINY_LOG_H_
#define __TINY_LOG_H_

#ifndef _MSVC_LANG
#if _MSC_FULL_VER <= 150030729 // before Visual Studio 2008 sp1, set C++ 98
#define _MSVC_LANG 199711L
#elif _MSC_FULL_VER <= 180021114 // before Visual Studio 2013 Nobemver CTP, set C++ 11
#define _MSVC_LANG 201103L
#elif _MSC_FULL_VER <= 190023918 // before Visual Studio 2015 Update 2, set C++ 14
#define _MSVC_LANG 201402L
#endif // after Visual Studio 2015 Update 3, _MSVC_LANG exists
#endif

#define USED_MILLISEC
//#define USED_MICROSEC

#define USED_LOCKFREE_QUEUE

#define ENABLED_BATCH_WRITE   //是否启用批量写日志文件

#define PRINT_COLORFUL 1  // 是否启用彩色

#include <list>
#include <queue>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <codecvt>
#include <locale>
#include <condition_variable>
#if (_MSVC_LANG >= 201703L)
#include <filesystem>
#elif (_MSVC_LANG == 201402L)
#include <experimental/filesystem>
#elif (_MSVC_LANG == 201103L)
#include <filesystem>
#endif
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdarg.h>

#if (_MSC_VER == 1700)
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define thread_local  __declspec( thread )
#define alignas(size) __declspec(align(size))
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x0004
#endif

#if defined(_WIN32) || defined(_WIN64)
#define MY_FILE(x) strrchr(x,'\\')?strrchr(x,'\\')+1:x
#else
#define MY_FILE(x) strrchr(x,'/')?strrchr(x,'/')+1:x
#endif

#if defined(_WIN32) || defined(_WIN64)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

namespace tlog
{
#if (_MSVC_LANG >= 201402L)
    static const std::string LOG_RESET = "\033[0m";
    static const std::string LOG_BLACK = "\033[30m";      /* Black */
    static const std::string LOG_RED = "\033[31m";      /* Red */
    static const std::string LOG_GREEN = "\033[32m";      /* Green */
    static const std::string LOG_YELLOW = "\033[33m";      /* Yellow */
    static const std::string LOG_BLUE = "\033[34m";      /* Blue */
    static const std::string LOG_MAGENTA = "\033[35m";      /* Magenta */
    static const std::string LOG_CYAN = "\033[36m";      /* Cyan */
    static const std::string LOG_WHITE = "\033[37m";      /* White */
#else
	static const char* LOG_RESET = "\033[0m";
    static const char* LOG_BLACK = "\033[30m";      /* Black */
    static const char* LOG_RED = "\033[31m";      /* Red */
    static const char* LOG_GREEN = "\033[32m";      /* Green */
    static const char* LOG_YELLOW = "\033[33m";      /* Yellow */
    static const char* LOG_BLUE = "\033[34m";      /* Blue */
    static const char* LOG_MAGENTA = "\033[35m";      /* Magenta */
    static const char* LOG_CYAN = "\033[36m";      /* Cyan */
    static const char* LOG_WHITE = "\033[37m";      /* White */
#endif

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>

    inline DWORD enableColorful()
    {
#if PRINT_COLORFUL
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE)
        {
            return GetLastError();
        }

        DWORD dwMode = 0;
        if (!GetConsoleMode(hOut, &dwMode))
        {
            return GetLastError();
        }

        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (!SetConsoleMode(hOut, dwMode))
        {
            return GetLastError();
        }
#endif
        return 0;
    }

    inline bool is_ansi_supported() 
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) 
        {
            return false;
        }

        DWORD mode;
        if (!GetConsoleMode(hConsole, &mode)) 
        {
            return false;
        }

        // Check if ENABLE_VIRTUAL_TERMINAL_PROCESSING is enabled
        return (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }
#endif

#ifdef ERROR
#undef ERROR
#endif

#ifdef max
#undef max
#endif

#ifndef LOCKFREE_QUEUE_SIZE
#define LOCKFREE_QUEUE_SIZE     4096
#endif

#if 0
    inline std::string pid()
    {
        std::stringstream ss;
#if (_MSC_VER < 1910)
		ss << boost::this_thread::get_id();
#else
        ss << std::this_thread::get_id();
#endif
        return ss.str();
    };
#endif

	inline std::string pid()
	{
		std::stringstream ss_pid;
#if defined(_WIN32) || defined(_WIN64)
		ss_pid << GetCurrentProcessId();
#else
		ss_tid << getpid();
#endif
		return ss_pid.str();
	};

	inline std::string tid()
	{
		std::stringstream ss_tid;
#if defined(_WIN32) || defined(_WIN64)
		ss_tid << GetCurrentThreadId();
#else
		ss_tid << gettid();
#endif
		return ss_tid.str();
	};

#if (_MSVC_LANG > 201402L)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    struct Destructible_codecvt_byname : public std::codecvt_byname<wchar_t, char, std::mbstate_t>
    {
        Destructible_codecvt_byname(const char* __str, std::size_t refs = 0) : codecvt_byname(__str, refs) {}
        // 注意：隐式析构函数为公开
    };

    // string的编码方式为utf8，则采用：
    inline std::string wstr2utf8str(const std::wstring& str)
    {
        static std::wstring_convert<std::codecvt_utf8<wchar_t> > strCnv;
        return strCnv.to_bytes(str);
    };

    inline std::wstring utf8str2wstr(const std::string& str)
    {
        static std::wstring_convert< std::codecvt_utf8<wchar_t> > strCnv;
        return strCnv.from_bytes(str);
    };

    // string的编码方式为除utf8外的其它编码方式，可采用：
    inline std::string wstr2gbkstr(const std::wstring& str, const std::string& locale)
    {
        typedef Destructible_codecvt_byname F;
        static std::wstring_convert<F> strCnv(new F(locale.c_str()));

        return strCnv.to_bytes(str);
    };

    inline std::wstring gbkstr2wstr(const std::string& str, const std::string& locale)
    {
        typedef Destructible_codecvt_byname F;
        static std::wstring_convert<F> strCnv(new F(locale.c_str()));

        return strCnv.from_bytes(str);
    };
#if (_MSVC_LANG > 201402L)
#pragma warning(pop)
#endif

	inline std::string utf8_to_gbk(const std::string& src)
	{
		std::wstring wtxt = utf8str2wstr(src);
		std::string gbktxt = wstr2gbkstr(wtxt, "Chinese");
		return gbktxt;
	};

	inline std::string gbk_to_utf8(const std::string& src)
	{
		std::wstring wtxt = gbkstr2wstr(src, "Chinese");
        std::string utf8txt = wstr2utf8str(wtxt);
		return utf8txt;
	};

#define LOG_PAUSE(msg) Logger::pause(LogTime::now().formatTime()+" [PAUSE]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", msg);

#define LOG_EMERG(format, ...) Logger::facade(Priority::EMERG, LogTime::now().formatTime()+" [EMERG]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_FATAL(format, ...) Logger::facade(Priority::FATAL, LogTime::now().formatTime()+" [FATAL]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_ALERT(format, ...) Logger::facade(Priority::ALERT, LogTime::now().formatTime()+" [ALERT]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_CRIT(format, ...) Logger::facade(Priority::CRIT, LogTime::now().formatTime()+" [CRIT]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_ERROR(format, ...) Logger::facade(Priority::ERROR, LogTime::now().formatTime()+" [ERROR]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_WARN(format, ...) Logger::facade(Priority::WARN, LogTime::now().formatTime()+" [WARN]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_INFO(format, ...) Logger::facade(Priority::INFO, LogTime::now().formatTime()+" [INFO]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_TRACE(format, ...) Logger::facade(Priority::TRACE, LogTime::now().formatTime()+" [TRACE]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);
#define LOG_DEBUG(format, ...) Logger::facade(Priority::DEBUG, LogTime::now().formatTime()+" [DEBUG]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", format, ##__VA_ARGS__);

#define HEX_DUMP(title, hexdata, len) Logger::hexdump(Priority::HEX, LogTime::now().formatTime()+" [HEX]["+tid()+"]["+(MY_FILE(__FILE__))+":"+std::to_string(__LINE__)+"-->"+__FUNCTION__ + "] ", title, hexdata, len);

    /***********************************************/
    class LogTime
    {
    public:
        LogTime() : timestamp_(0)
        {}

        explicit LogTime(uint64_t timestamp) : timestamp_(timestamp)
        {}

        static LogTime now();

        std::string date() const;

        std::string dateTime() const;

        std::string formatTime() const;

    private:
        uint64_t timestamp_;
        static const uint32_t SEC = 1000000;
        static const uint16_t MILLISEC = 1000;
        static const uint16_t MICROSEC = 1;
    };

    /***********************************************/
    class TimeCounter
    {
    public:
        TimeCounter() : begin_time(std::chrono::high_resolution_clock::now()) {}

        ~TimeCounter() {}

        void reset()
        {
            begin_time = std::chrono::high_resolution_clock::now();
        }

        //输出毫秒
        uint64_t elapsed_milli() const
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        //微秒
        uint64_t elapsed_micro() const
        {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        //纳秒
        uint64_t elapsed_nano() const
        {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        //秒
        uint64_t elapsed_seconds() const
        {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        //分
        uint64_t elapsed_minutes() const
        {
            return std::chrono::duration_cast<std::chrono::minutes>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        //时
        uint64_t elapsed_hours() const
        {
            return std::chrono::duration_cast<std::chrono::hours>(
                std::chrono::high_resolution_clock::now() - begin_time).count();
        }

        std::string format_thousands(uint64_t num, char separator = ' ') const
        {
            std::string numStr = std::to_string(num);
            int len = numStr.length();

            // 从后往前每隔3位插入分隔符
            for (int i = len - 3; i > 0; i -= 3) {
                numStr.insert(i, 1, separator);
            }

            return numStr;
        }
    private:
        std::chrono::time_point<std::chrono::high_resolution_clock> begin_time;
    };

    /***********************************************/
    class LogBuffer
    {
    public:
        enum status
        {
            FULL = 1,
            FREE = 0
        };

        explicit LogBuffer(uint64_t len);

        bool append(const std::string& str);

        void setStatus(status sta);

        status getStatus() const
        {
            return curr_status;
        };

        std::string getData()
        {
            return data;
        };

        bool empty() const
        {
            return can_use == max_size;
        }

    private:
        status curr_status;
        uint64_t curr_pos;
        int64_t can_use;
        std::string data;
        uint64_t max_size;
    };

	/***********************************************/
    //安全队列
	template<typename T>
	class LogSafeQueue
	{
	public:
		void push(T value)
        {
            std::lock_guard<std::mutex> lock(mtx);	// 加锁
            LogSafeQueue::q.push(std::move(value));
            cv.notify_one();
        };

		T wait_and_pop()
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [this] { return !q.empty(); });
            T value = std::move(q.front());
            q.pop();
            return value;
        };

		bool empty() 
        {
            return q.empty();
        };
	private:
		std::queue<T> q;
		std::mutex mtx;
		std::condition_variable cv;
	};

    /***********************************************/
    //无锁队列
    template<typename T>
    class LockFreeRingBuffer
    {
    public:
        explicit LockFreeRingBuffer(size_t capacity) 
            : _buffer_(capacity), 
              _capacity_(capacity),
              _mask_(capacity - 1),
              _head_(0),
              _tail_(0)
        {
            if ((capacity & (capacity - 1)) != 0) 
            {
                throw std::invalid_argument("Capacity must be power of 2");
            }
        }

        bool push(const T& item)
        {
            while (true)
            {
                size_t current_tail = _tail_.load(std::memory_order_relaxed);
                //size_t next_tail = (current_tail + 1) % _capacity_;
                size_t next_tail = (current_tail + 1) & _mask_;
                size_t current_head = _head_.load(std::memory_order_acquire);

                //检查队列是否已满
                if (next_tail == current_head) return false;    //队列满, 返回失败

                // 尝试原子更新_tail_（从current_tail到next_tail）
                if (_tail_.compare_exchange_weak(current_tail, next_tail, std::memory_order_release, std::memory_order_relaxed)) 
                {
                    // 更新成功，写入数据
                    _buffer_[current_tail] = item;
                    return true;
                }

                // 更新失败，重新计算next_tail（current_tail已被其他线程修改）
            }

            //size_t current_tail = _tail_.load(std::memory_order_relaxed);
            //size_t next_tail = (current_tail + 1) % _capacity_;
            //size_t next_tail = (current_tail + 1) & _mask_;
            //while (next_tail == _head_.load(std::memory_order_acquire));

            //_buffer_[current_tail] = item;
            //_tail_.store(next_tail, std::memory_order_release);
            //return true;
        };

        bool pop(T& item)
        {
            while (true)
            {
                size_t current_head = _head_.load(std::memory_order_relaxed);
                size_t current_tail = _tail_.load(std::memory_order_acquire);

                // 检查队列是否为空
                if (current_head == current_tail) return false;     //队列空, 返回失败

                item = _buffer_[current_head];
                size_t next_head = (current_head + 1) & _mask_;

                // 尝试原子更新_head_
                if (_head_.compare_exchange_weak(current_head, next_head, std::memory_order_release, std::memory_order_relaxed)) 
                    return true;

                // 更新失败，重试
            }
            //size_t current_head = _head_.load(std::memory_order_relaxed);

            //检查队列是否为空
            //while (current_head == _tail_.load(std::memory_order_acquire));

            //item = _buffer_[current_head];
            //_head_.store((current_head + 1) % _capacity_, std::memory_order_release);
            //_head_.store((current_head + 1) & _mask_, std::memory_order_release);
            //return true;
        };

        bool empty() const
        {
            return _head_.load(std::memory_order_acquire) ==
                _tail_.load(std::memory_order_acquire);
        };

        bool full() const
        {
            //size_t next_tail = (_tail_.load(std::memory_order_relaxed) + 1) % _capacity_;
			size_t next_tail = (_tail_.load(std::memory_order_relaxed) + 1) & _mask_;
            return next_tail == _head_.load(std::memory_order_acquire);
        };

        size_t size() const
        {
            size_t head = _head_.load(std::memory_order_acquire);
            size_t tail = _tail_.load(std::memory_order_acquire);

            if (tail >= head)
            {
                return tail - head;
            }

            return _capacity_ - (head - tail);
        };

        bool clear()
        {
            _buffer_.clear();
            _buffer_.shrink_to_fit();
            _head_.store(0, std::memory_order_release);
            _tail_.store(0, std::memory_order_release);
            return empty();
        };
    private:
        std::vector<T> _buffer_;
        const size_t _capacity_;
        const size_t _mask_;
        alignas(64) std::atomic<size_t> _head_;      //防止伪共享
        alignas(64) std::atomic<size_t> _tail_;
    };

     /***********************************************/
    class LogFile
    {

    public:
        LogFile(const std::string& exe_name, const std::string& path, const uintmax_t size);

        static uintmax_t getFileSize(const std::string& file_name);

        static bool is_utf8(const std::string& data);

        void writeMessage(const std::string& msg);

        ~LogFile();

    public:
        std::ofstream file;
        std::string curr_file_name;
        std::string path;
        uintmax_t max_size;
        std::string exe_name;
    private:
        void rotateFile(const uintmax_t msg_size);

#if (_MSC_VER >= 1800)
        uintmax_t current_size = 0;
        uint32_t N = 0;
#else
        uintmax_t current_size;
        uint32_t N;
#endif
    };

    /***********************************************/

	class Priority 
	{
	public:
		typedef enum {
                      EMERG  = 0,               // 紧急（系统无法使用）
                      FATAL  = 10,              // 致命（程序崩溃）
                      ALERT  = 100,             // 立即处理（如数据库连接失败）
                      CRIT   = 200,             // 重要提示信息（如文件无法打开）
                      ERROR  = 300,             // 错误（如参数无效）
                      WARN   = 400,             // 警告（如配置项缺失）
                      INFO   = 500,             // 信息（如程序启动）
                      TRACE  = 600,             // 跟踪（如函数调用路径）
                      DEBUG  = 700,             // 调试（如变量值）
					  HEX    = 800,             // 十六进制Dump
                      NOTSET = 900              // 未设置（不输出任何日志）
        } PriorityLevel;
		
		typedef int Value;
	};

    typedef unsigned char byte;
    class Logger
    {
    public:
#if (_MSC_VER >= 1800)
        explicit Logger() = default;

        ~Logger() = default;

        Logger& operator = (const Logger&) = delete;  	// 声明拷贝赋值操作是已删除函数

        Logger(const Logger&) = delete;                	// 声明构造拷贝是已删除函数

        void* operator new (std::size_t) = delete;      // 声明new构建对象是已删除函数

        void* operator new[](std::size_t) = delete;     // 声明new构建对象数组是已删除函数

        void operator delete (void* ptr) = delete;     // 声明delete删除对象是已删除函数

        void operator delete[](void* ptr) = delete;    //  声明delete删除对象数组是已删除函数
#else
        explicit Logger();

        ~Logger();
#endif

#if (_MSC_VER >= 1800)
        template<typename... Types>
        static void facade(const Priority::Value cur_lv, const std::string& prefix, const char* fmt, const Types&...args) {   //按照可变参数进行数据格式化
#else
        static void facade(const Priority::Value cur_lv, const std::string & prefix, const char* fmt, ...) {    //按照可变参数进行数据格式化
#endif
            std::atomic<bool> writefile;

            //level=NOTSET(900),cur_lv=NOTSET(900) 关闭所有日志, 跳过NOTSET级别
            if ((level == Priority::NOTSET || cur_lv == Priority::NOTSET) && !console) return;

            //过滤低级别日志
            writefile.store(((level >= cur_lv) && (level != Priority::NOTSET)), std::memory_order_relaxed);
            if (!writefile.load(std::memory_order_relaxed) && !console) return;

#if (_MSC_VER >= 1800)
            const auto len = snprintf(nullptr, 0, fmt, args...);
            std::string msg;
            msg.resize(static_cast<size_t>(len) + 1);
            snprintf(&msg.front(), len + 1, fmt, args...);  //可变参数导入
            msg.resize(static_cast<size_t>(len));
#elif (_MSC_VER == 1700)
#pragma warning(push)
#pragma warning(disable: 4996)
            va_list va;
            va_start(va, fmt);
            const auto len = vsnprintf(nullptr, 0, fmt, va);
            std::string msg;
            msg.resize(static_cast<size_t>(len) + 1);
            vsnprintf(&msg.front(), len + 1, fmt, va);  //可变参数导入
            msg.resize(static_cast<size_t>(len));
            va_end(va);
#pragma warning(pop)
#endif
            std::string final_msg;
            final_msg.reserve(prefix.size() + msg.size() + 1); // +1 for '\n'
            final_msg.append(prefix);
            final_msg.append(msg);
            final_msg.push_back('\n');

            if (writefile.load(std::memory_order_relaxed))
                addToBuffer(final_msg);

            if (console)
            {
                switch (cur_lv) {
                case Priority::EMERG: case Priority::FATAL: color = LOG_RED; break;
                case Priority::ALERT: case Priority::CRIT: color = LOG_YELLOW; break;
                case Priority::ERROR: color = LOG_MAGENTA; break;
                case Priority::WARN: color = LOG_BLUE; break;
                case Priority::INFO: case Priority::TRACE: color = LOG_CYAN; break;
                case Priority::DEBUG: color = LOG_GREEN; break;
                default: break;
                }

                addToConsole(color, final_msg);
            }
        };

        static void hexdump(const Priority::Value cur_lv, const std::string& prefix, const std::string& title, const byte* hexdata, int len);

        static void initLogger(const std::string& argv, bool console = false, Priority::Value level = Priority::INFO, uint64_t len = 4096,
            const std::string& path = "./log", uintmax_t size = 1000 * 10 * 1024);//默认单个文件10MB

        static inline void pause(const std::string& prefix, const std::string& msg)
        {
            facade(Priority::EMERG, prefix, msg.c_str());
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cin.get();
        }

        //TODO 日志关闭功能，目前仅仅是使用延时来等待关闭前保证数据写入
        static void lazyDownLogger();

    private:
        static void write(const std::string& msg);

        static inline std::string tohex(const int len, const int bits) {
            std::stringstream ioss;
            ioss << std::hex << std::setw(bits) << std::setfill('0') << len;
            return ioss.str();
        };

        static inline std::string tohex(const byte hexchar) {
            std::stringstream ioss;
            ioss << std::hex << std::setw(2) << std::setfill('0') << (int)hexchar;
            return ioss.str();
        };

        static void addToBuffer(const std::string& msg);

        static void addToConsole(const std::string& color_, const std::string& msg);

    private:
#if (defined(USED_LOCKFREE_QUEUE))
        static LockFreeRingBuffer<std::string> log_queue;       //log日志队列
        static LockFreeRingBuffer<std::string> console_queue;   //控制台队列
#else   
        static std::list<std::shared_ptr<LogBuffer>> log_data;  //log数据
        static LogSafeQueue<std::string> console_queue;         //控制台队列
        static std::shared_ptr<LogBuffer> curr_in_buffer;       //当前的写入buffer
        static std::shared_ptr<LogBuffer> curr_out_buffer;      //当前的持久化buffer
        static std::mutex mu;
        static std::condition_variable cv;
#endif
        static std::shared_ptr<LogFile> file;
        static uint64_t len;
        static std::string path;
        static uintmax_t size;
        static std::mutex console_mu;
        static std::condition_variable console_cv;
#if (_MSC_VER < 1910)
		static std::shared_ptr<boost::thread> th;
        static std::shared_ptr<boost::thread> th_;
		static std::shared_ptr<boost::thread> console_th;
#else
        static std::shared_ptr<std::thread> th;
        static std::shared_ptr<std::thread> th_;
		static std::shared_ptr<std::thread> console_th;
#endif
        static std::atomic<bool> _exit_flag;    //线程退出标志
        static bool ready;
		static bool console;
        static bool ansi_supported;
#if (_MSVC_LANG >= 201402L)
        static thread_local std::string color;
#else
		static thread_local const char* color;
#endif
        static Priority::Value level;         //日志级别开关
    };
}

#endif //__TINY_LOG_H_
