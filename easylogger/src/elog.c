/*
 * This file is part of the EasyLogger Library.
 *
 * Copyright (c) 2015-2018, Armink, <armink.ztl@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Function: Initialize function and other general function.
 * Created on: 2015-04-28
 */
/* TODO: 增加一个开启无限长输出的配置宏，不开启时，使用标注库中的vsnprintf实现单行输出，最原始的方案；开启后，不再依赖标准库，但需添加printf函数，日志输出将不限制行长度
开启无限长输出的配置宏：在该printf函数中：
    1、向缓冲区中丢数据
    2、判断缓冲区是否写满，写满时则自动调用输出函数执行一次数据输出
    3、切换缓冲区，重复执行1，直至数据填充完毕
    4、主动调用输出函数将剩余数据输出

    20240411：
    不实用宏，使用弱函数的方式来决定是否使用无限长功能：
        在该文件中定义一个 vfctprintf 的弱函数。
        在未实现该函数的时候：
            保持现有功能不变的前提下，在elog_strstr中增加对是否实现该弱函数的功能判断(已完成)，并保持现有功能不变。
        在实现该函数后：
            elog_strstr中判断不是弱函数，接着判断缓冲区是否已满，满的时候直接执行一次数据输出。
*/
/* //TODO:
备用缓冲区用于解决类似DMA输出时，由于串口数据打印速率低于CPU写数据速率，未输出的数据被覆盖的问题。
    不使用额外的备用缓冲区时，将设置的缓冲区大小一分为二作为备用缓冲区。
    环形缓冲区不能解决该问题，因为无法得知DMA是否输出完毕，这就导致第二次写入可能会覆盖上次的数据
 */
#define LOG_TAG "elog"

#include "../inc/elog.h"
#include <stdarg.h>
#include <stdio.h>

#if ELOG_OUTPUT_ENABLE

#define ELOG_USE_TINY_PRINTF 1

#if !defined(ELOG_OUTPUT_LVL)
#error "Please configure static output log level (in elog_cfg.h)"
#endif

#if !defined(ELOG_OUTPUT_BUF_SIZE)
#error "Please configure buffer size for every line's log (in elog_cfg.h)"
#endif

#if !defined(ELOG_FILTER_TAG_MAX_LEN)
#error "Please configure output filter's tag max length (in elog_cfg.h)"
#endif

#if !defined(ELOG_NEWLINE_SIGN)
#error "Please configure output newline sign (in elog_cfg.h)"
#endif

/* output filter's tag level max num */
#ifndef ELOG_FILTER_TAG_MAX_NUM
#define ELOG_FILTER_TAG_MAX_NUM 4
#endif

/* output line number string max length */
#define ELOG_FMT_LINE_MAX_LEN 5

#if ELOG_COLOR_ENABLE
/**
 * CSI(Control Sequence Introducer/Initiator) sign
 * more information on https://en.wikipedia.org/wiki/ANSI_escape_code
 */
#define CSI_START                       "\033["
#define CSI_END                         "\033[0m"
/* output log front color */
#define F_BLACK                         "30;"
#define F_RED                           "31;"
#define F_GREEN                         "32;"
#define F_YELLOW                        "33;"
#define F_BLUE                          "34;"
#define F_MAGENTA                       "35;"
#define F_CYAN                          "36;"
#define F_WHITE                         "37;"
/* output log background color */
#define B_NULL
#define B_BLACK                         "40;"
#define B_RED                           "41;"
#define B_GREEN                         "42;"
#define B_YELLOW                        "43;"
#define B_BLUE                          "44;"
#define B_MAGENTA                       "45;"
#define B_CYAN                          "46;"
#define B_WHITE                         "47;"
/* output log fonts style */
#define S_BOLD                          "1m"
#define S_UNDERLINE                     "4m"
#define S_BLINK                         "5m"
#define S_NORMAL                        "22m"
/* output log default color definition: [front color] + [background color] + [show style] */
#ifndef ELOG_COLOR_ASSERT
#define ELOG_COLOR_ASSERT               (F_MAGENTA B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_ERROR
#define ELOG_COLOR_ERROR                (F_RED B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_WARN
#define ELOG_COLOR_WARN                 (F_YELLOW B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_INFO
#define ELOG_COLOR_INFO                 (F_CYAN B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_DEBUG
#define ELOG_COLOR_DEBUG                (F_GREEN B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_VERBOSE
#define ELOG_COLOR_VERBOSE              (F_BLUE B_NULL S_NORMAL)
#endif
#endif /* ELOG_COLOR_ENABLE */

/* __e_weak and __e_inline Definitions */
#if defined(__ARMCC_VERSION)        /* ARM Compiler */
#define __e_weak                        __attribute__((weak))
#elif defined (__IAR_SYSTEMS_ICC__) /* for IAR Compiler */
#define __e_weak                        __weak
#elif defined (__GNUC__)            /* GNU GCC Compiler */
#define __e_weak                        __attribute__((weak))
#elif defined (__ADSPBLACKFIN__)    /* for VisualDSP++ Compiler */
#define __e_weak                        __attribute__((weak))
#elif defined (_MSC_VER)
#define __e_weak
#elif defined (__TI_COMPILER_VERSION__)
/* The way that TI compiler set section is different from other(at least
 * GCC and MDK) compilers. See ARM Optimizing C/C++ Compiler 5.9.3 for more
 * details. */
#ifdef __TI_EABI__
#define __e_weak                        __attribute__((weak))
#else
#define __e_weak
#endif
#elif defined (__TASKING__)
#define __e_weak                        __attribute__((weak))
#else
    #error not supported tool chain
#endif /* __ARMCC_VERSION */

/* easy logger */
typedef struct {
    /* output log's filter */
    struct {
        uint8_t basic_lvl :7; /**< basic level filter for global, lower than tags filter */
        uint8_t enabled   :1; /**< false : filter is no used   true: filter is used */
#if ELOG_FILTER_TAG_ENABLE
        struct {
            uint8_t level   :7;
            uint8_t enabled :1; /**< false : tag is no used   true: tag is used */
            char tag[ELOG_FILTER_TAG_MAX_LEN + 1];
        } tag_filters[ELOG_FILTER_TAG_MAX_NUM];
#endif /* ELOG_FILTER_TAG_ENABLE */
    } filter;

    ElogFmtIndex lvl_fmt[ELOG_FILTER_LVL_ALL + 1]; /**< output format for each level */
    size_t output_buff_size;
    uint8_t init_ok                         :1;
    uint8_t weak_vfuncprintf                :1;
    uint8_t buff_swap                       :1;
    uint8_t output_enabled                  :1;
    uint8_t output_lock_enabled             :1;
    uint8_t output_is_locked_before_enable  :1;
    uint8_t output_is_locked_before_disable :1;
} EasyLogger;

/* output_arg for vfctprintf */
typedef struct {
    bool in_isr;
    char *buff;
    size_t buff_size;
    size_t pos;
} output_arg;

/* EasyLogger object */
static EasyLogger elog;

/* every line log's buffer */
static char log_buf_normal[((ELOG_OUTPUT_BUF_SIZE >> 1) << 1)] = { 0 };
#if ELOG_USING_IN_ISR
static char log_buf_isr[((ELOG_OUTPUT_BUF_SIZE >> 1) << 1)] = { 0 };
#endif

/* level output info */
static const char *level_output_info[] = {
    [ELOG_LVL_ASSERT]  = "A/",
    [ELOG_LVL_ERROR]   = "E/",
    [ELOG_LVL_WARN]    = "W/",
    [ELOG_LVL_INFO]    = "I/",
    [ELOG_LVL_DEBUG]   = "D/",
    [ELOG_LVL_VERBOSE] = "V/",
};

#if ELOG_COLOR_ENABLE
/* color output info */
static const char *color_output_info[] = {
    [ELOG_LVL_ASSERT]  = ELOG_COLOR_ASSERT,
    [ELOG_LVL_ERROR]   = ELOG_COLOR_ERROR,
    [ELOG_LVL_WARN]    = ELOG_COLOR_WARN,
    [ELOG_LVL_INFO]    = ELOG_COLOR_INFO,
    [ELOG_LVL_DEBUG]   = ELOG_COLOR_DEBUG,
    [ELOG_LVL_VERBOSE] = ELOG_COLOR_VERBOSE,
};
#endif /* ELOG_COLOR_ENABLE */

/* EasyLogger assert hook */
void (*elog_assert_hook)(const char *expr, const char *func, size_t line);

extern void elog_port_console_output(bool in_isr, const char *log, size_t size);
extern void elog_port_backend_output(bool in_isr, uint32_t appender, uint8_t level,
                                     const char *time, size_t time_len,
                                     const char *info, size_t info_len,
                                     const char *log, size_t log_len);
extern bool elog_port_lock(bool in_isr, uint32_t appender);
extern bool elog_port_unlock(bool in_isr, uint32_t appender);
#if ELOG_ASYNC_OUTPUT_ENABLE
extern void elog_async_output(uint8_t level, const char *log, size_t size);
#endif /* ELOG_ASYNC_OUTPUT_ENABLE */
#if ELOG_BUF_OUTPUT_ENABLE
extern void elog_buf_output(const char *log, size_t size);
#endif /* ELOG_BUF_OUTPUT_ENABLE */

/* utils */

static void putc_func(char c, void *extra_arg)
{
    output_arg *buff_arg = (output_arg *)extra_arg;
    buff_arg->buff[buff_arg->pos] = c;
    if (buff_arg->pos + 1 < buff_arg->buff_size)
        buff_arg->pos++;
    else { //TODO: buff is full, output it now

    }
}

void putchar_(char c)
{
}

__e_weak int vfctprintf(void (*func)(char c, void *extra_arg), void *extra_arg, const char *format, va_list arg)
{
    output_arg *buff_arg;
    if (!extra_arg)
        return -ELOG_EDENY;
    buff_arg = (output_arg *)extra_arg;
    return vsnprintf(buff_arg->buff, buff_arg->buff_size, format, arg);
}

/**
 * @brief Returns a pointer to the first occurrence of s2 in s1, or a null pointer if s2 is not part of s1,
 *      where the search is limited to the first slen characters of s1.
 *
 * @param s1 C string to be scanned.
 * @param s2 C string containing the sequence of characters to match.
 * @param len search length limited of s1
 *
 * @return A pointer to the first occurrence in s1 of the entire sequence of characters specified in s2,
 *      or a null pointer if the sequence is not present in s1.
 */
static char *elog_strnstr(const char *s1, const char *s2, size_t len)
{
    size_t pos, i;

    if (!*s2)
        return (0);

    pos = 0;
    while (s1[pos] != '\0' && pos < len) {
        if (s1[pos] == s2[0]) {
            i = 1;
            while ((s2[i] != '\0') && (s1[pos + i] == s2[i]) && (pos + i < len))
                ++i;
            if (s2[i] == '\0')
                return ((char *)&s1[pos]);
        }
        ++pos;
    }
    return (0);
}

/**
 * @brief another copy string function
 *
 * @param cur_len current copied log length, max size is elog.output_buff_size
 * @param dst destination
 * @param src source
 *
 * @return copied length
 */
static size_t elog_strcpy(size_t cur_len, char *dst, const char *src)
{
    const char *src_old = src;

    if (!dst || !src) return (0);

    while (*src != 0) {
        /* make sure destination has enough space */
        if (cur_len++ < elog.output_buff_size) {
            *dst++ = *src++;
        } else if (!elog.weak_vfuncprintf) { //TODO: buff is full, output it now
            break;
        } else {
            break;
        }
    }
    return src - src_old;
}

/**
 * @brief another strncpy function, it will copy the '\0' to dest
 *
 * @return dest addr
 */
static char *elog_strncpy(char *dest, const char *src, int len)
{
    char *temp;
    if (!dest || !src)
        return (char *)0;

    temp = src;
    for (int i = 0; i <len; i++, temp++, src++) {
        *temp = *src;
        if (*src == '\0')
            break;
    }
    return dest;
}

void elog_set_output_enabled(bool enabled)
{
    ELOG_ASSERT((enabled == false) || (enabled == true));

    elog.output_enabled = enabled;
}

bool elog_get_output_enabled(void)
{
    return elog.output_enabled;
}

void elog_output_lock_enabled(bool enabled, bool in_isr, uint32_t appender)
{
    elog.output_lock_enabled = enabled;
    /* it will re-lock or re-unlock before output lock enable */
    if (elog.output_lock_enabled) {
        if (!elog.output_is_locked_before_disable && elog.output_is_locked_before_enable) {
            /* the output lock is unlocked before disable, and the lock will unlocking after enable */
#if ELOG_USING_IN_ISR
            elog_port_lock(in_isr, appender);
#else
            elog_port_lock(false, appender);
#endif /* ELOG_USING_IN_ISR */
        } else if (elog.output_is_locked_before_disable && !elog.output_is_locked_before_enable) {
            /* the output lock is locked before disable, and the lock will locking after enable */
#if ELOG_USING_IN_ISR
            elog_port_unlock(in_isr, appender);
#else
            elog_port_unlock(false, appender);
#endif /* ELOG_USING_IN_ISR */
        }
    }
}

ElogErrCode elog_output_lock(bool in_isr, uint32_t appender)
{
    if (elog.output_lock_enabled) {
#if ELOG_USING_IN_ISR
        if (elog_port_lock(in_isr, appender))
#else
        if (elog_port_lock(false, appender))
#endif /* ELOG_USING_IN_ISR */
        {
            elog.output_is_locked_before_disable = true;
            return ELOG_EOK;
        }
        return ELOG_ELOCK_FAILED;
    }

    elog.output_is_locked_before_enable = true;
    return ELOG_EOK;
}

ElogErrCode elog_output_unlock(bool in_isr, uint32_t appender)
{
    if (elog.output_lock_enabled) {
#if ELOG_USING_IN_ISR
        if (elog_port_unlock(in_isr, appender))
#else
        if (elog_port_unlock(false, appender))
#endif /* ELOG_USING_IN_ISR */
        {
            elog.output_is_locked_before_disable = false;
            return ELOG_EOK;
        }
        return ELOG_ELOCK_FAILED;
    }

    elog.output_is_locked_before_enable = false;
    return ELOG_EOK;
}

void elog_set_fmt(uint8_t level, size_t format)
{
    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);

    elog.lvl_fmt[level] = format;
}

void elog_set_filter(uint8_t level, bool enabled)
{
    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);
    ELOG_ASSERT((enabled == false) || (enabled == true));

    elog.filter.basic_lvl = level;
    elog.filter.enabled = enabled;
}

#if ELOG_FILTER_TAG_ENABLE
ElogErrCode elog_set_filter_tag(const char *tag, uint8_t level)
{
    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);
    ELOG_ASSERT(tag != ((void *)0));
    uint8_t i = 0;
    ElogErrCode ret = ELOG_EFAILED;

    if (!elog.init_ok || !elog.filter.enabled) {
        return ELOG_EDENY;
    }

    if (ELOG_EOK != elog_output_lock(false, ELOG_APD_ALL))
        return ELOG_ELOCK_FAILED;

    /* find the tag in arr */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        if (elog.filter.tag_filters[i].enabled &&
            elog_strnstr(tag, elog.filter.tag_filters[i].tag, ELOG_FILTER_TAG_MAX_LEN)) {
            break;
        }
    }

    if (i < ELOG_FILTER_TAG_MAX_NUM) {
        /* find OK */
        if (level >= ELOG_FILTER_LVL_ALL) {
            /* remove current tag's level filter when input level is the lowest level */
            elog.filter.tag_filters[i].enabled = false;
            elog.filter.tag_filters[i].level = ELOG_FILTER_LVL_SILENT;
        } else {
            elog.filter.tag_filters[i].level = level;
        }
        ret = ELOG_EOK;
    } else if (level < ELOG_FILTER_LVL_ALL) {
        /* only add the new tag's level filer when level is not ELOG_FILTER_LVL_ALL */
        ret = ELOG_ENO_SPACE;
        for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
            if (!elog.filter.tag_filters[i].enabled) {
                elog_strncpy(elog.filter.tag_filters[i].tag, tag, ELOG_FILTER_TAG_MAX_LEN);
                elog.filter.tag_filters[i].level = level;
                elog.filter.tag_filters[i].enabled = true;
                ret = ELOG_EOK;
                break;
            }
        }
    }

    if (ELOG_EOK != elog_output_unlock(false, ELOG_APD_ALL))
        return ELOG_EUNLOCK_FAILED;

    return ret;
}

uint8_t elog_get_filter_tag_lvl(const char *tag)
{
    ELOG_ASSERT(tag != ((void *)0));
    uint8_t i = 0;
    uint8_t level = ELOG_LVL_VERBOSE;

    if (!elog.init_ok || !elog.filter.enabled) {
        return level;
    }

    if (ELOG_EOK != elog_output_lock(false, ELOG_APD_ALL))
        return level;

    /* find the tag in arr */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        if (elog.filter.tag_filters[i].enabled == true &&
            elog_strnstr(tag, elog.filter.tag_filters[i].tag, ELOG_FILTER_TAG_MAX_LEN)) {
            level = elog.filter.tag_filters[i].level;
            break;
        }
    }
    elog_output_unlock(false, ELOG_APD_ALL);

    return level;
}
#endif /* ELOG_FILTER_TAG_ENABLE */

void elog_assert_set_hook(void (*hook)(const char *expr, const char *func, size_t line))
{
    elog_assert_hook = hook;
}

ElogErrCode elog_init(void)
{
    extern ElogErrCode elog_port_init(void);
    extern ElogErrCode elog_async_init(void);

    ElogErrCode result = ELOG_EOK;
    uint8_t i = 0;
    va_list args;

    if (elog.init_ok == true) {
        return result;
    }

    /* get the vfctprintf state and initialize the output buff size */
    if (-ELOG_EDENY == vfctprintf(NULL, NULL, NULL, args)) {
        elog.weak_vfuncprintf = 1;
    } else {
        elog.weak_vfuncprintf = 0;
    }
    elog.output_buff_size = (ELOG_OUTPUT_BUF_SIZE >> 1) << elog.weak_vfuncprintf;
    elog.buff_swap = false;

    /* output locked status initialize */
    elog.output_is_locked_before_enable = false;
    elog.output_is_locked_before_disable = false;
    /* enable the output lock */
    elog_output_lock_enabled(true, false, ELOG_APD_ALL);

    /* set basic level is ELOG_OUTPUT_LVL */
    elog_set_filter(ELOG_OUTPUT_LVL, false);
    /* set log format to none */
    for (i = 0; i <= ELOG_FILTER_LVL_ALL; i++) {
        elog.lvl_fmt[i] = 0;
    }

#if ELOG_FILTER_TAG_ENABLE
    /* set tag_level to default val */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        elog.filter.tag_filters[i].level = ELOG_FILTER_LVL_SILENT;
        elog.filter.tag_filters[i].enabled = false;
    }
#endif /* ELOG_FILTER_TAG_ENABLE */

    /* port initialize */
    result = elog_port_init();
    if (result != ELOG_EOK) {
        return result;
    }

#if ELOG_ASYNC_OUTPUT_ENABLE
    result = elog_async_init();
    if (result != ELOG_EOK) {
        return result;
    }
#endif

    elog.init_ok = true;

    return result;
}

void elog_deinit(void)
{
    extern ElogErrCode elog_port_deinit(void);
    extern ElogErrCode elog_async_deinit(void);

    if (!elog.init_ok) {
        return;
    }

#if ELOG_ASYNC_OUTPUT_ENABLE
    elog_async_deinit();
#endif

    /* port deinitialize */
    elog_port_deinit();

    elog.init_ok = false;
}

void elog_start(void)
{
    if (!elog.init_ok) {
        return;
    }

    /* enable output */
    elog_set_output_enabled(true);

#if ELOG_ASYNC_OUTPUT_ENABLE
    elog_async_enabled(true);
#elif ELOG_BUF_OUTPUT_ENABLE
    elog_buf_enabled(true);
#endif

    /* show version */
    LOG_I("EasyLogger V%s is initialize success.", ELOG_SW_VERSION);
}

void elog_stop(void)
{
    if (!elog.init_ok) {
        return;
    }

    /* disable output */
    elog_set_output_enabled(false);

#if ELOG_ASYNC_OUTPUT_ENABLE
    elog_async_enabled(false);
#elif ELOG_BUF_OUTPUT_ENABLE
    elog_buf_enabled(false);
#endif

    /* show version */
    LOG_D("EasyLogger V%s is deinitialize success.", ELOG_SW_VERSION);
}

static char *get_log_buff(bool in_isr)
{
#if ELOG_USING_IN_ISR
    char *buff = log_buf_normal;
    if (in_isr) {
        buff = log_buf_isr;
    }
    if (elog.weak_vfuncprintf) {
        return log_buf_normal;
    } else if (buff_swap) {
        buff_swap = false;
        return buff + elog.output_buff_size;
    }
    buff_swap = true;
    return buff;
#else
    if (elog.weak_vfuncprintf) {
        return log_buf_normal;
    } else if (elog.buff_swap) {
        elog.buff_swap = false;
        return log_buf_normal + elog.output_buff_size;
    }
    elog.buff_swap = true;
    return log_buf_normal;
#endif
}

void elog_raw_output(bool in_isr, uint32_t appender, const char *format, ...)
{
    va_list args;
    size_t log_len = 0;
    int fmt_result;
    char *log_buf = NULL;
    output_arg raw_output_arg;

    /* check output appender */
    if (!elog.output_enabled || !appender) {
        return;
    }

    /* lock output */
    if (ELOG_EOK != elog_output_lock(in_isr, appender))
        return;

    /* args point to the first variable parameter */
    va_start(args, format);

    log_buf = get_log_buff(in_isr);

    /* package log data to buffer */
    raw_output_arg.buff      = log_buf;
    raw_output_arg.buff_size = elog.output_buff_size;
    raw_output_arg.pos       = 0;
    raw_output_arg.in_isr    = in_isr;
    fmt_result = vfctprintf(putc_func, &raw_output_arg, format, args);

    /* output converted log */
    if ((fmt_result > -1) && (fmt_result <= elog.output_buff_size)) {
        log_len = fmt_result;
    } else {
        log_len = elog.output_buff_size;
    }
    /* output log */
#if ELOG_ASYNC_OUTPUT_ENABLE
    extern void elog_async_output(uint8_t level, const char *log, size_t size);
    /* raw log will using assert level */
    elog_async_output(ELOG_LVL_ASSERT, log_buf, log_len);
#elif ELOG_BUF_OUTPUT_ENABLE
    elog_buf_output(log_buf, log_len);
#else
    if (appender & ELOG_APD_CONSOLE)
        elog_port_console_output(in_isr, log_buf, log_len);

    if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
        elog_port_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), ELOG_LVL_DEBUG,
                                 NULL, 0,
                                 NULL, 0,
                                 log_buf, log_len);
#endif
    /* unlock output */
    elog_output_unlock(in_isr, appender);

    va_end(args);
}

void elog_output(bool in_isr, uint32_t appender, uint8_t level,
                 const char *tag, const char *file, const char *func, const long line,
                 const char *format, ...)
{
    extern const char *elog_port_get_time(void);
    extern const char *elog_port_get_p_info(void);
    extern const char *elog_port_get_t_info(void);

    size_t level_format = elog.lvl_fmt[level], log_len = 0, time_len, fmt_info_len, raw_log_len;
    char *log_buf = NULL, *time_addr = NULL, *fmt_info_addr = NULL, *raw_log_addr = NULL;
    int fmt_result;
    uint8_t tag_level = ELOG_LVL_VERBOSE;
    output_arg log_output_arg;
    va_list args;
#ifdef DIR_NAME_FUNC_FLAG
    uint8_t dir_name_func_not_null = 0;
    char line_num[ELOG_FMT_LINE_MAX_LEN + 1] = { 0 };
#endif /* DIR_NAME_FUNC_FLAG */
#if ELOG_FMT_NAME_ENABLE
    char *file_name = NULL;
#endif

    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);

    /* check output appender */
    if (!elog.output_enabled || !appender) {
        return;
    }

    /* level filter */
    if (elog.filter.enabled) {
#if ELOG_FILTER_TAG_ENABLE
        tag_level = elog_get_filter_tag_lvl(tag);
        if (tag_level < ELOG_FILTER_LVL_ALL) { // tag is existing in filter
            if (tag_level < level)
                return;
        } else
#endif /* ELOG_FILTER_TAG_ENABLE */
        {
            if (elog.filter.basic_lvl < level) {
                return;
            }
        }
    }

    /* lock output */
    if (ELOG_EOK != elog_output_lock(in_isr, appender)) {
        return;
    }

    /* args point to the first variable parameter */
    va_start(args, format);

    log_buf = get_log_buff(in_isr);

#if ELOG_COLOR_ENABLE
    /* add CSI start sign and color info */
    log_len += elog_strcpy(log_len, log_buf + log_len, CSI_START);
    log_len += elog_strcpy(log_len, log_buf + log_len, color_output_info[level]);
#endif

    /* package time */
    time_len = 0;
    if (level_format & ELOG_FMT_TIME) {
        log_len += elog_strcpy(log_len, log_buf + log_len, "[");
        time_addr = log_buf + log_len;
        time_len = elog_strcpy(log_len, time_addr, elog_port_get_time());
        log_len += time_len;
        log_len += elog_strcpy(log_len, log_buf + log_len, "] ");
    }

    /* record the fmt info addr: "tag[p:p_info t:t_info][.\dir\filename.c:line function] */
    fmt_info_addr = log_buf + log_len;

    /* package level info */
    if (level_format & ELOG_FMT_LVL) {
        log_len += elog_strcpy(log_len, log_buf + log_len, level_output_info[level]);
    }
    /* package tag info */
    if (level_format & ELOG_FMT_TAG) {
        log_len += elog_strcpy(log_len, log_buf + log_len, tag);
    }
    /* package process and thread info */
    if (level_format & (ELOG_FMT_P_INFO | ELOG_FMT_T_INFO)) {
        log_len += elog_strcpy(log_len, log_buf + log_len, "[");
        /* package process info */
        if (level_format & ELOG_FMT_P_INFO) {
            log_len += elog_strcpy(log_len, log_buf + log_len, "p:");
            log_len += elog_strcpy(log_len, log_buf + log_len, elog_port_get_p_info());

            if (level_format & ELOG_FMT_T_INFO)
                log_len += elog_strcpy(log_len, log_buf + log_len, " ");
        }
        /* package thread info */
        if (level_format & ELOG_FMT_T_INFO) {
            log_len += elog_strcpy(log_len, log_buf + log_len, "t:");
            log_len += elog_strcpy(log_len, log_buf + log_len, elog_port_get_t_info());
        }
        log_len += elog_strcpy(log_len, log_buf + log_len, "]");
    }
    /* package file directory and name, function name and line number info */
#if ELOG_FMT_DIR_ENABLE
    if (level_format & ELOG_FMT_DIR) dir_name_func_not_null = 1;
#endif
#if ELOG_FMT_NAME_ENABLE
    if (level_format & ELOG_FMT_NAME) dir_name_func_not_null = 1;
#endif
#if ELOG_FMT_FUNC_ENABLE
    if (level_format & ELOG_FMT_FUNC) dir_name_func_not_null = 1;
#endif
#ifdef DIR_NAME_FUNC_FLAG
    if (dir_name_func_not_null) log_len += elog_strcpy(log_len, log_buf + log_len, "[");
#endif /* DIR_NAME_FUNC_FLAG */
#if ELOG_FMT_DIR_ENABLE
    /* Contains file path and file name */
    if (level_format & ELOG_FMT_DIR) {
        /* package file name info */
        log_len += elog_strcpy(log_len, log_buf + log_len, file);
        log_len += elog_strcpy(log_len, log_buf + log_len, ":");
#elif ELOG_FMT_NAME_ENABLE
    /* get file name */
    if (level_format & ELOG_FMT_NAME) {
        file_name = strrchr(file, '\\');                       // windows
        if (file_name == NULL) file_name = strrchr(file, '/'); // linux
        if (file_name == NULL)
            file_name = (char *)file;
        else
            file_name++;
        /* package file name info */
        log_len += elog_strcpy(log_len, log_buf + log_len, (const char *)file_name);
        log_len += elog_strcpy(log_len, log_buf + log_len, ":");
#elif defined(DIR_NAME_FUNC_FLAG)
    if (dir_name_func_not_null) {
#endif  /* ELOG_FMT_DIR_ENABLE */
        /* package line info */
#ifdef DIR_NAME_FUNC_FLAG
        snprintf(line_num, ELOG_FMT_LINE_MAX_LEN, "%ld", line);
        log_len += elog_strcpy(log_len, log_buf + log_len, line_num);
#endif /* DIR_NAME_FUNC_FLAG */
#if ELOG_FMT_FUNC_ENABLE
        if (level_format & ELOG_FMT_FUNC) log_len += elog_strcpy(log_len, log_buf + log_len, ":");
#endif /* ELOG_FMT_FUNC_ENABLE */
#ifdef DIR_NAME_FUNC_FLAG
    }
#endif /* DIR_NAME_FUNC_FLAG */

#if ELOG_FMT_FUNC_ENABLE
    /* package func info */
    if (level_format & ELOG_FMT_FUNC) log_len += elog_strcpy(log_len, log_buf + log_len, func);
#endif /* ELOG_FMT_FUNC_ENABLE */
#ifdef DIR_NAME_FUNC_FLAG
    if (dir_name_func_not_null) log_len += elog_strcpy(log_len, log_buf + log_len, "]");
#endif /* DIR_NAME_FUNC_FLAG */

    /* reacquire the fmt info addr and fmt info len */
    if ((log_buf + log_len) == fmt_info_addr) {
        fmt_info_addr = NULL;
        fmt_info_len = 0;
    } else {
        fmt_info_len = log_buf + log_len - fmt_info_addr;
        log_len += elog_strcpy(log_len, log_buf + log_len, ": ");
    }

    /* package other log data to buffer. '\0' must be added in the end by vsnprintf. */
    raw_log_addr = log_buf + log_len;

    log_output_arg.buff      = raw_log_addr;
    log_output_arg.buff_size = elog.output_buff_size - log_len;
    log_output_arg.pos       = 0;
    log_output_arg.in_isr    = in_isr;
    fmt_result = vfctprintf(putc_func, &log_output_arg, format, args);

    va_end(args);
    /* calculate log length */
    if ((log_len + fmt_result <= elog.output_buff_size) && (fmt_result > -1)) {
        log_len += fmt_result;
    } else {
        /* using max length */
        log_len = elog.output_buff_size;
    }
    /* overflow check and reserve some space for CSI end sign and newline sign */
#if ELOG_COLOR_ENABLE
    if (log_len + (sizeof(CSI_END) - 1) + (sizeof(ELOG_NEWLINE_SIGN) - 1) > elog.output_buff_size) {
        /* using max length */
        log_len = elog.output_buff_size;
        /* reserve some space for CSI end sign */
        log_len -= (sizeof(CSI_END) - 1);
        /* reserve some space for newline sign */
        log_len -= (sizeof(ELOG_NEWLINE_SIGN) - 1);
    }
#else
    if (log_len + (sizeof(ELOG_NEWLINE_SIGN) - 1) > elog.output_buff_size) {
        /* using max length */
        log_len = elog.output_buff_size;
        /* reserve some space for newline sign */
        log_len -= (sizeof(ELOG_NEWLINE_SIGN) - 1);
    }
#endif /* ELOG_COLOR_ENABLE */

    /* reacquire the raw log addr and raw log len */
    if ((log_buf + log_len) == raw_log_addr) {
        raw_log_addr = NULL;
        raw_log_len = 0;
    } else {
        raw_log_len = log_buf + log_len - raw_log_addr;
    }

#if ELOG_COLOR_ENABLE
    /* add CSI end sign */
    log_len += elog_strcpy(log_len, log_buf + log_len, CSI_END);
#endif
    /* package newline sign */
    log_len += elog_strcpy(log_len, log_buf + log_len, ELOG_NEWLINE_SIGN);

    /* output log */
#if ELOG_ASYNC_OUTPUT_ENABLE
    elog_async_output(level, log_buf, log_len);
#elif ELOG_BUF_OUTPUT_ENABLE
    elog_buf_output(log_buf, log_len);
#else
    if (appender & ELOG_APD_CONSOLE)
        elog_port_console_output(in_isr, log_buf, log_len);

    if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
        elog_port_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), level,
                                 time_addr, time_len,
                                 fmt_info_addr, fmt_info_len,
                                 raw_log_addr, raw_log_len);
#endif
    /* unlock output */
    elog_output_unlock(in_isr, appender);
}

static void hex_in_char(uint8_t hex, char *s)
{
    char up_hex[16] = "0123456789ABCDEF";
    unsigned char i = 0;
    while (hex > 0x0F){
        i++;
        hex -= 0x10;
    }
    *s++ = up_hex[i];
    *s = up_hex[hex];
}

void elog_hexdump(bool in_isr, uint32_t appender, const char *name, uint8_t width, const void *buf, uint16_t size)
{
#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

    uint16_t i = 0, j = 0, log_len = 0;
    const uint8_t *buf_p = buf;
    char *log_buf = NULL, dump_string[8] = { 0 };

    /* check output appender */
    if (!elog.output_enabled || !appender) {
        return;
    }

    /* level filter */
    if (elog.filter.enabled && (elog.filter.basic_lvl < ELOG_LVL_DEBUG)) {
        return;
    }

    /* lock output */
    if (ELOG_EOK != elog_output_lock(in_isr, appender)) {
        return;
    }

    /* package start line */
    log_buf = get_log_buff(in_isr);
    log_len += elog_strcpy(log_len, log_buf + log_len, "D/HEX: ");
    log_len += elog_strcpy(log_len, log_buf + log_len, name);
    goto __do_log_out;

    while (i < size) {
        log_buf = get_log_buff(in_isr);
        log_len = 0;
        /* package header */
        hex_in_char(i >> 8, log_buf + log_len);
        log_len += 2;
        hex_in_char(i & 0xFF, log_buf + log_len);
        log_len += 2;
        log_buf[log_len++] = '-';
        hex_in_char((i + width - 1) >> 8, log_buf + log_len);
        log_len += 2;
        hex_in_char((i + width - 1) & 0xFF, log_buf + log_len);
        log_len += 2;
        log_buf[log_len++] = ':';
        log_buf[log_len++] = ' ';

        /* dump hex */
        dump_string[2] = ' ';
        dump_string[3] = '\0';
        for (j = 0; j < width; j++) {
            if (i + j < size) {
                hex_in_char(buf_p[i + j], dump_string);
            } else {
                dump_string[0] = ' ';
                dump_string[1] = ' ';
            }
            log_len += elog_strcpy(log_len, log_buf + log_len, dump_string);
            if ((j + 1) % 8 == 0) {
                log_len += elog_strcpy(log_len, log_buf + log_len, " ");
            }
        }
        log_len += elog_strcpy(log_len, log_buf + log_len, "  ");
        /* dump char for hex */
        dump_string[1] = '\0';
        for (j = 0; j < width; j++) {
            if (i + j < size) {
                dump_string[0] = __is_print(buf_p[i + j]) ? buf_p[i + j] : '.';
                log_len += elog_strcpy(log_len, log_buf + log_len, dump_string);
            }
        }
        i += width;

__do_log_out:
        /* overflow check and reserve some space for newline sign */
        if (log_len + (sizeof(ELOG_NEWLINE_SIGN) - 1) > elog.output_buff_size) {
            log_len = elog.output_buff_size - (sizeof(ELOG_NEWLINE_SIGN) - 1);
        }
        /* package newline sign */
        log_len += elog_strcpy(log_len, log_buf + log_len, ELOG_NEWLINE_SIGN);

        /* do log output */
#if ELOG_ASYNC_OUTPUT_ENABLE
        elog_async_output(ELOG_LVL_DEBUG, log_buf, log_len);
#elif ELOG_BUF_OUTPUT_ENABLE
        elog_buf_output(log_buf, log_len);
#else
        if (appender & ELOG_APD_CONSOLE)
            elog_port_console_output(in_isr, log_buf, log_len);

        if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
            elog_port_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), ELOG_LVL_DEBUG,
                                     NULL, 0,
                                     NULL, 0,
                                     log_buf, log_len);
#endif
    }
    /* unlock output */
    elog_output_unlock(in_isr, appender);
#undef __is_print
}
#endif /* ELOG_OUTPUT_ENABLE */
