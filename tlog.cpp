#include "tlog.h"

using namespace tlog;

#if (_MSVC_LANG >= 201703L)
namespace fs = std::filesystem;
#elif (_MSVC_LANG == 201402L)
namespace fs = std::experimental::filesystem;
#elif (_MSVC_LANG == 201103L)
namespace fs = std::tr2::sys;
#endif

#if (_MSC_VER < 1800)
Logger::Logger()
{
}

Logger::~Logger()
{
}
#endif

/*****************************************************************************************/
#if (defined(USED_LOCKFREE_QUEUE))
LockFreeRingBuffer<std::string> Logger::log_queue(LOCKFREE_QUEUE_SIZE);
LockFreeRingBuffer<std::string> Logger::console_queue(LOCKFREE_QUEUE_SIZE);
#else
std::list<std::shared_ptr<LogBuffer>>  Logger::log_data;
LogSafeQueue<std::string> Logger::console_queue;
std::shared_ptr<LogBuffer> Logger::curr_in_buffer = nullptr;
std::shared_ptr<LogBuffer> Logger::curr_out_buffer = nullptr;
std::mutex Logger::mu;
std::condition_variable Logger::cv;
#endif
std::shared_ptr<LogFile> Logger::file = nullptr;
uint64_t Logger::len;
std::string Logger::path;
uintmax_t Logger::size;
std::mutex Logger::console_mu;
std::condition_variable Logger::console_cv;
#if (_MSC_VER < 1910)
std::shared_ptr<boost::thread> Logger::th;
std::shared_ptr<boost::thread> Logger::th_;
std::shared_ptr<boost::thread> Logger::console_th;
#else
std::shared_ptr<std::thread> Logger::th;
std::shared_ptr<std::thread> Logger::th_;
std::shared_ptr<std::thread> Logger::console_th;
#endif
std::atomic<bool> Logger::_exit_flag;
bool Logger::ready = false;
bool Logger::console = false;
bool Logger::ansi_supported = false;
#if (_MSVC_LANG >= 201402L)
thread_local std::string Logger::color;
#else
thread_local const char* Logger::color = nullptr;
#endif
int Logger::level = Priority::INFO;

void Logger::write(const std::string & msg)
{
    file->writeMessage(std::move(msg));
}

void Logger::hexdump(const Priority::Value cur_lv, const std::string & prefix, const std::string & title, const byte * hexdata, int len)
{
    if (cur_lv != Priority::HEX) return;	//hexdump不接收cur_lv=HEX以外的任何日志请求

    if (hexdata == nullptr)     // 判断hexdata是否为空
    {
        throw std::invalid_argument("argument:hexdata is invalid, is nullptr");
        return;
    }

    std::atomic<bool> writefile;

    //level=NOTSET(900),cur_lv=NOTSET(900) 关闭所有日志, 跳过NOTSET级别
    if ((level == Priority::NOTSET || cur_lv == Priority::NOTSET) && !console) return;

    //过滤低级别日志
    writefile.store(((level >= cur_lv) && (level != Priority::NOTSET)), std::memory_order_relaxed);
    if (!writefile.load(std::memory_order_relaxed) && !console) return;
	
    color = LOG_GREEN;
    int i, j;
    std::stringstream titlestream;
    titlestream << title << " size:[0x" << tohex(len, 4);
    titlestream << "(" << len << ")]" << std::endl;

    std::string final_msg;
    final_msg.reserve(prefix.size() + titlestream.str().size() + 1); // +1 for '\n'
    final_msg.append(prefix);
    final_msg.append(titlestream.str());
	if(writefile.load(std::memory_order_relaxed))
		addToBuffer(final_msg);
    if (console)
        addToConsole(color, final_msg);

	if(writefile.load(std::memory_order_relaxed))
		addToBuffer(" ====== =1==2==3==4==5==6==7==8=Hex=9==a==b==c==d==e==f==0= ======Ascii======\n");
    if (console)
    {
        std::string msg = " ====== =1==2==3==4==5==6==7==8=Hex=9==a==b==c==d==e==f==0= ======Ascii======\n";
        addToConsole(color, msg);
    }

    std::stringstream ss;
    for (i = 0; i < len / 16; i++)
    {
        ss << " " << tohex(i * 16, 4) << "h: ";
        for (j = 0; j < 16; j++)
        {
            if (j == 8)
                ss << "   ";
            ss << tohex(hexdata[i * 16 + j]) << " ";
        }
        ss << "|";
        for (j = 0; j < 16; j++)
        {
            if (j == 8)
                ss << " ";
            if (hexdata[i * 16 + j] >= 0x21 && hexdata[i * 16 + j] <= 0x7e)
            {
                ss << hexdata[i * 16 + j];
            }
            else
            {
                ss << ".";
            }
        }
        ss << std::endl;
    }
    //if (len % 16 != 0)
    if ((len & 15) != 0)
    {
        ss << " " << tohex(i * 16, 4) << "h: ";
        //for (j = 0; j < len % 16; j++)
        for (j = 0; j < (len & 15); j++)
        {
            if (j == 8)
                ss << "   ";
            ss << tohex(hexdata[i * 16 + j]) << " ";
        }
        //if (len % 16 > 8)
        if ((len & 15) > 8)
        {
            //for (j = 0; j < (48 - (len % 16) * 3); j++)
            for (j = 0; j < (48 - (len & 15) * 3); j++)
                ss << " ";
        }
        //else if (len % 16 <= 8)
        else if ((len & 15) <= 8)
        {
            //for (j = 0; j < (51 - (len % 16) * 3); j++)
            for (j = 0; j < (51 - (len & 15) * 3); j++)
                ss << " ";
        }
        ss << "|";
        //for (j = 0; j < 0 + len % 16; j++)
        for (j = 0; j < 0 + (len & 15); j++)
        {
            if (j == 8)
                ss << " ";
            if (hexdata[i * 16 + j] >= 0x21 && hexdata[i * 16 + j] <= 0x7e)
            {
                ss << hexdata[i * 16 + j];
            }
            else
            {
                ss << ".";
            }
        }
        ss << std::endl;
    }
	if(writefile.load(std::memory_order_relaxed))
		addToBuffer(ss.str());
    if (console)
        addToConsole(color, ss.str());

	if(writefile.load(std::memory_order_relaxed))
		addToBuffer(" ====== =================================================== =================\n");
    if (console)
    {
        std::string msg = " ====== =================================================== =================\n";
        addToConsole(color, msg);
    }
}

void Logger::addToBuffer(const std::string & msg)
{
#if (defined(USED_LOCKFREE_QUEUE))
    int retry = 0;
    while (!log_queue.push(std::move(msg)) && retry++ < 10)  //失败, 重试10次
    {
        //std::cerr << "\nlog queue is full, please wait a moment for retry.";
        // 队列满时休眠避免忙等
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        //std::this_thread::yield();
    }
#else
    std::unique_lock<std::mutex> mut(mu);
    if ((*log_data.begin())->append(msg))
    {
    }
    else
    {
        //auto* temp = new LogBuffer(len);
        //curr_in_buffer = std::shared_ptr<LogBuffer>(temp);
        curr_in_buffer = std::make_shared<LogBuffer>(len);
        log_data.emplace_front(curr_in_buffer);
        (*log_data.begin())->append(msg);
        ready = true;
        cv.notify_all();
    }
#endif
}

void Logger::addToConsole(const std::string& color_, const std::string& msg)
{
    std::string colored_msg;

#if defined(_WIN32) || defined(_WIN64)
    if (ansi_supported)
    {
        // 用ANSI转义码
#if (_MSVC_LANG >= 201402L)
        colored_msg.reserve(LOG_RESET.size() + color_.size() + msg.size() + LOG_RESET.size());
#else
        colored_msg.reserve(strlen(LOG_RESET) + color_.size() + msg.size() + strlen(LOG_RESET));
#endif
        colored_msg.append(LOG_RESET);
        colored_msg.append(color_);
        colored_msg.append(msg);
        colored_msg.append(LOG_RESET);
    }
    else
    {
        colored_msg.append(msg);
    }
#else
#if (_MSVC_LANG >= 201402L)
    colored_msg.reserve(LOG_RESET.size() + color_.size() + msg.size() + LOG_RESET.size());
#else
    colored_msg.reserve(strlen(LOG_RESET) + color_.size() + msg.size() + strlen(LOG_RESET));
#endif
    colored_msg.append(LOG_RESET);
    colored_msg.append(color_);
    colored_msg.append(msg);
    colored_msg.append(LOG_RESET);
#endif

    console_queue.push(std::move(colored_msg));
    std::lock_guard<std::mutex> lock(console_mu);
    console_cv.notify_all();
}

void Logger::initLogger(const std::string & argv, bool console_, Priority::Value level_, uint64_t len_, 
						const std::string & path_, uintmax_t size_)
{
    len = len_;
    path = path_;
    size = size_;
    ready = false;
	console = console_;
    level = level_;
#if defined(_WIN32) || defined(_WIN64)
    enableColorful();
    ansi_supported = is_ansi_supported();
#endif
    //auto x = new LogFile(argv, path, size);
    //file = std::shared_ptr<LogFile>(x);
    file = std::make_shared<LogFile>(argv, path, size);
    _exit_flag.store(false, std::memory_order_relaxed);
#if (defined(USED_LOCKFREE_QUEUE))
    auto xth = ([&]
        {
#if (defined(ENABLED_BATCH_WRITE))
            const size_t BATCH_SIZE = 100;    // 批量处理数量
            const int MAX_WAIT_MS = 10;       // 最大等待时间(毫秒)

            std::vector<std::string> batch;
            batch.reserve(BATCH_SIZE);
#endif

            while (!_exit_flag.load(std::memory_order_relaxed))
            {
                std::string msg;
#if (defined(ENABLED_BATCH_WRITE))
                int wait_count = 0;
                while (batch.size() < BATCH_SIZE)
                {
                    if (log_queue.pop(msg))     // 从队列取日志
                    {
                        batch.push_back(std::move(msg));
                        wait_count = 0;  // 重置等待计数
                    }
                    else
                    {
                        // 队列空时短暂等待
                        if (++wait_count > MAX_WAIT_MS) break;
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                }

                // 批量写入文件
                if (!batch.empty())
                {
                    // 合并日志消息
                    std::string combined;
                    combined.reserve(len * batch.size());  // 预分配内存

                    for (auto& msg : batch)
                    {
                        combined += std::move(msg);
                    }

                    write(combined);  // 单次文件写入
                    batch.clear();
                }
                else if (_exit_flag.load(std::memory_order_relaxed))
                {
                    break;  // 关闭时无日志则退出
                }
#else
                if (log_queue.pop(msg))     // 从队列取日志
                {
                    write(msg);             // 直接写入文件
                }
                else
                {
                    // 队列为空时休眠避免忙等
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
#endif
            }

#if (defined(ENABLED_BATCH_WRITE))
            // 退出前确保写入剩余日志
            if (!batch.empty())
            {
                std::string combined;
                for (auto& msg : batch)
                {
                    combined += std::move(msg);
                }
                write(combined);
            }
#endif
        });
#if (_MSC_VER < 1910)
    th = std::make_shared<boost::thread>(xth);
#else
    th = std::make_shared<std::thread>(xth);
#endif
#else
    //auto* temp = new LogBuffer(len);
    //curr_in_buffer = std::shared_ptr<LogBuffer>(temp);
    curr_in_buffer = std::make_shared<LogBuffer>(len);
    log_data.emplace_back(curr_in_buffer);
    curr_out_buffer = log_data.back();
    auto xth = ([&]
        {
            while (!_exit_flag.load(std::memory_order_relaxed))
            {
                std::unique_lock<std::mutex> lck(mu);
                // 如果标志位不为true，则等待
                cv.wait(lck, [&]
                    { return ready; });
                //auto* temp = new LogBuffer(len);
                if (!curr_in_buffer->empty())
                {
                    curr_in_buffer->setStatus(LogBuffer::status::FULL);
                    //curr_in_buffer = std::shared_ptr<LogBuffer>(temp);
                    curr_in_buffer = std::make_shared<LogBuffer>(len);
                    log_data.emplace_front(curr_in_buffer);
                }
                file->file.open(path + "/" + file->curr_file_name,
                    std::ios::binary | std::ios::app | std::ios::in | std::ios::out);
                while (curr_in_buffer != curr_out_buffer)
                {
                    if (curr_out_buffer->getStatus() == LogBuffer::status::FULL)
                    {
                        std::string msg = (log_data.back())->getData();
                        write(msg);
                    }
                    log_data.pop_back();
                    curr_out_buffer = log_data.back();
                }
                file->file.close();
                ready = false;
                lck.unlock();
            }
        });
#if (_MSC_VER < 1910)
	th = std::make_shared<boost::thread>(xth);
#else
    th = std::make_shared<std::thread>(xth);
#endif
    auto x_ = ([&]
        {
            while (!_exit_flag.load(std::memory_order_relaxed))
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                //std::this_thread::sleep_for(std::chrono::milliseconds(500));
                std::unique_lock<std::mutex> lck(mu);
                ready = true;
                cv.notify_all();
                lck.unlock();
            }
        });
#if (_MSC_VER < 1910)
	th_ = std::make_shared<boost::thread>(x_);
#else
    th_ = std::make_shared<std::thread>(x_);
#endif
#endif
	auto cth = ([&]
        {
            while (!_exit_flag.load(std::memory_order_relaxed))
            {
                std::unique_lock<std::mutex> lock(console_mu);
                // 等待队列非空（避免忙等）
                console_cv.wait(lock, []() {
                    return _exit_flag.load(std::memory_order_relaxed) || 
                    !console_queue.empty(); 
                    });

                // 优先检查退出条件
                if (_exit_flag.load(std::memory_order_relaxed)) break;  // 安全退出

#if (defined(USED_LOCKFREE_QUEUE))
                std::string msg;
                console_queue.pop(msg);
#else
			    std::string msg = console_queue.wait_and_pop();
#endif
				/*if (LogFile::is_utf8(msg))
				{
					std::wstring wtxt = utf8str2wstr(msg);
					std::string gbktxt = wstr2gbkstr(wtxt, "Chinese");
					std::cout << gbktxt;
				}
				else
					std::cout<< msg;*/

                lock.unlock();
				std::cout<< msg;
            }
        });
#if (_MSC_VER < 1910)
	console_th = std::make_shared<boost::thread>(cth);
#else
	console_th = std::make_shared<std::thread>(cth);
#endif

#if (defined(USED_LOCKFREE_QUEUE))
    th->detach();
#else
    th_->detach();
    th->detach();
#endif
	console_th->detach();
}

void Logger::lazyDownLogger()
{
    _exit_flag.store(true, std::memory_order_relaxed);

    if (console_th && console_th->joinable())
        console_th->join();     //等待控制台打印线程退出

    if (!console_queue.empty())
    {
        console_queue.clear();
    }

#if (defined(USED_LOCKFREE_QUEUE))
    // 等待日志队列清空
    while (!log_queue.empty()) 
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (th && th->joinable())
        th->join();     // 等待写入线程退出

    if (!log_queue.empty())
    {
        log_queue.clear();
    }
#else
    //写缓存延时2秒
    while (!log_data.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (th && th->joinable())
        th->join();     // 等待写入线程退出

    if (th_ && th_->joinable())
        th_->join();     // 等待定时守护线程退出

    if(!log_data.empty())
        log_data.clear();
#endif
}

/*****************************************************************************************/

LogBuffer::LogBuffer(uint64_t len) : max_size(len), curr_pos(0), can_use(len), curr_status(status::FREE)
{}

bool LogBuffer::append(const std::string & str)
{
    if (str.length() > can_use)
    {
        setStatus(status::FULL);
        can_use = 0;
        curr_pos = max_size;
        return false;
    }
    else
    {
        data.append(str);
        curr_pos += str.length();
        can_use -= str.length();
        return true;
    }
}

void LogBuffer::setStatus(status sta)
{
    curr_status = sta;
}

/*****************************************************************************************/

LogFile::LogFile(const std::string & exe_name, const std::string & path, const uintmax_t size) 
:exe_name(exe_name), path(path), max_size(size), current_size(0), N(0)  //初始化curr_size为0, N为0
{
#if (_MSVC_LANG >= 201402L)
    if (!fs::exists(path))
    {
        fs::create_directories(path);
    }
    fs::path p(exe_name);
    std::string f = p.filename().string();
#elif (_MSVC_LANG == 201103L)
    N = 0;
    fs::path p = path;
    if (!fs::exists(p))
    {
        fs::create_directories(p);
    }
    fs::path e = exe_name;
    auto f = e.filename();
#endif

    curr_file_name = f.substr(0, f.rfind(".")) + "_" + LogTime::now().date() + "(" + std::to_string(N) + ")" + ".log";
    file.open(path + PATH_SEPARATOR + curr_file_name, std::ios::binary | std::ios::app | std::ios::in | std::ios::out);
    if (file.is_open())
    {
        file.seekp(0, std::ios::end);
        current_size = file.tellp();
    }
}

uintmax_t LogFile::getFileSize(const std::string & file_name)
{
#if (_MSVC_LANG >= 201402L)
    return fs::file_size(file_name);
#elif (_MSVC_LANG == 201103L)
    fs::path p = file_name;
    return fs::file_size(p);
#endif
}

bool LogFile::is_utf8(const std::string & data)
{
    if (!data.c_str())
        return true;

    const unsigned char* bytes = (const unsigned char*)data.c_str();
    unsigned int cp;
    int num;

    while (*bytes != 0x00)
    {
        if ((*bytes & 0x80) == 0x00)
        {
            // U+0000 to U+007F 
            cp = (*bytes & 0x7F);
            num = 1;
        }
        else if ((*bytes & 0xE0) == 0xC0)
        {
            // U+0080 to U+07FF 
            cp = (*bytes & 0x1F);
            num = 2;
        }
        else if ((*bytes & 0xF0) == 0xE0)
        {
            // U+0800 to U+FFFF 
            cp = (*bytes & 0x0F);
            num = 3;
        }
        else if ((*bytes & 0xF8) == 0xF0)
        {
            // U+10000 to U+10FFFF 
            cp = (*bytes & 0x07);
            num = 4;
        }
        else
            return false;

        bytes += 1;
        for (int i = 1; i < num; ++i)
        {
            if ((*bytes & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (*bytes & 0x3F);
            bytes += 1;
        }

        if ((cp > 0x10FFFF) ||
            ((cp >= 0xD800) && (cp <= 0xDFFF)) ||
            ((cp <= 0x007F) && (num != 1)) ||
            ((cp >= 0x0080) && (cp <= 0x07FF) && (num != 2)) ||
            ((cp >= 0x0800) && (cp <= 0xFFFF) && (num != 3)) ||
            ((cp >= 0x10000) && (cp <= 0x1FFFFF) && (num != 4)))
            return false;
    }

    return true;
}

void LogFile::rotateFile(const uintmax_t msg_size)
{
    do {
        if (file.is_open())
        {
            file.close();
        }
        N++;

        // ...生成新文件名逻辑...
#if (_MSVC_LANG >= 201402L)
        fs::path p(exe_name);
        std::string f = p.filename().string();
        curr_file_name = f.substr(0, f.rfind(".")) + "_" + LogTime::now().date() + "(" + std::to_string(N) + ")" + ".log";
#elif (_MSVC_LANG == 201103L)
        fs::path e = exe_name;
        auto f = e.filename();
        curr_file_name = f.substr(0, f.rfind(".")) + "_" + LogTime::now().date() + "(" + std::to_string(N) + ")" + ".log";
#endif

        if (!file.is_open())
        {
            // 尝试打开文件
            file.open(path + PATH_SEPARATOR + curr_file_name, std::ios::binary | std::ios::app | std::ios::in | std::ios::out);
            if (file.is_open())
            {
                file.seekp(0, std::ios::end);
                current_size = file.tellp();
            }
        }
    } while (current_size + msg_size >= max_size);
}

void LogFile::writeMessage(const std::string & msg)
{
    uintmax_t msg_size = msg.size();

#if (_MSVC_LANG >= 201402L)
    if (fs::exists(path + PATH_SEPARATOR + curr_file_name))
    {
        if (current_size + msg_size > max_size)
        {
            //需要轮转
            rotateFile(msg_size);
        }
    }
#elif (_MSVC_LANG == 201103L)
    std::string filename = path + PATH_SEPARATOR + curr_file_name;
    fs::path p = filename;
    if (fs::exists(p))
    {
        if (current_size + msg_size > max_size)
        {
            //需要轮转
            rotateFile(msg_size);
        }
    }
#endif
    if (!file.is_open())
    {
        // 尝试打开文件
        file.open(path + PATH_SEPARATOR + curr_file_name, std::ios::binary | std::ios::app | std::ios::in | std::ios::out);
    }
    
	//保存为utf8编码格式文件
	/*if (!is_utf8(msg))
    {
        std::wstring wtxt = gbkstr2wstr(msg, "Chinese");
        std::string utf8txt = wstr2utf8str(wtxt);
        file << utf8txt;
    }*/
	//保存为gbk编码格式文件
    /*if (is_utf8(msg))
    {
		std::wstring wtxt = utf8str2wstr(msg);
		std::string gbktxt = wstr2gbkstr(wtxt, "Chinese");
		file << gbktxt;
    }
    else
    {
        file << msg;
    }*/

    file << msg;
    file.flush();   // 确保数据写入磁盘
    current_size += msg_size;
    //file.close();
}

LogFile::~LogFile()
{
    if (file.is_open())
    {
        file.close();
    }
}

/*****************************************************************************************/

LogTime LogTime::now()
{
    uint64_t timestamp;
    timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return LogTime(timestamp);
}

std::string LogTime::dateTime() const
{
#if (_MSC_VER >= 1800)
    static thread_local time_t sec = 0;
    static thread_local char datetime[22]{};//2023-11-02 12:05:27
#else
    thread_local static time_t sec = 0;
    thread_local static char datetime[22]; //2023-11-02 12:05:27
#endif
    time_t now_sec = timestamp_ / SEC;
    if (now_sec > sec)
    {
        sec = now_sec;
#if (_MSC_VER >= 1800)
        struct tm time_ {};
#else
        struct tm time_;
#endif
#ifdef __linux
        localtime_r(&sec, &time_);
#else
        localtime_s(&time_, &sec);
#endif // __linux

        strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", &time_);
    }
    return datetime;
}

std::string LogTime::date() const
{
#if (_MSC_VER >= 1800)
    static thread_local time_t sec = 0;
    static thread_local char date[10]{};//20231102
#else
    thread_local static time_t sec = 0;
    thread_local static char date[10]; //20231102
#endif
    time_t now_sec = timestamp_ / SEC;
    if (now_sec > sec)
    {
        sec = now_sec;
#if (_MSC_VER >= 1800)
        struct tm time_ {};
#else
        struct tm time_;
#endif
#ifdef __linux
        localtime_r(&sec, &time_);
#else
        localtime_s(&time_, &sec);
#endif // __linux

        strftime(date, sizeof(date), "%Y%m%d", &time_);
    }
    return date;
}

std::string LogTime::formatTime() const
{
#if (defined(USED_MILLISEC))
    char format[26];
    memset(format, 0x00, sizeof(format));
    std::string dts = dateTime();
    auto milli = static_cast<uint32_t>(timestamp_ % MILLISEC);
#if (_MSC_VER == 1700)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    snprintf(format, sizeof(format), "%s.%03u", dts.c_str(), milli);
#if (_MSC_VER == 1700)
#pragma warning(pop)
#endif
    return format;
#elif (defined(USED_MICROSEC))
    char format[29];
    memset(format, 0x00, sizeof(format));
    std::string dts = dateTime();
    auto micro = static_cast<uint32_t>(timestamp_ % SEC);
#if (_MSC_VER == 1700)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    snprintf(format, sizeof(format), "%s.%06u", dts.c_str(), micro);
#if (_MSC_VER == 1700)
#pragma warning(pop)
#endif
    return format;
#endif
}
