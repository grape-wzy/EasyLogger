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

#define LOG_TAG "elog"

#include <elog.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#if defined(ELOG_OUTPUT_ENABLE) && (ELOG_OUTPUT_ENABLE != 0)

#if !defined(ELOG_OUTPUT_LVL)
#error "Please configure static output log level (in elog_cfg.h)"
#endif

#if !defined(ELOG_LINE_BUF_SIZE)
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

#if defined(ELOG_COLOR_ENABLE) && (ELOG_COLOR_ENABLE != 0)
/**
 * CSI(Control Sequence Introducer/Initiator) sign
 * more information on https://en.wikipedia.org/wiki/ANSI_escape_code
 */
#define CSI_START "\033["
#define CSI_END   "\033[0m"
/* output log front color */
#define F_BLACK   "30;"
#define F_RED     "31;"
#define F_GREEN   "32;"
#define F_YELLOW  "33;"
#define F_BLUE    "34;"
#define F_MAGENTA "35;"
#define F_CYAN    "36;"
#define F_WHITE   "37;"
/* output log background color */
#define B_NULL
#define B_BLACK     "40;"
#define B_RED       "41;"
#define B_GREEN     "42;"
#define B_YELLOW    "43;"
#define B_BLUE      "44;"
#define B_MAGENTA   "45;"
#define B_CYAN      "46;"
#define B_WHITE     "47;"
/* output log fonts style */
#define S_BOLD      "1m"
#define S_UNDERLINE "4m"
#define S_BLINK     "5m"
#define S_NORMAL    "22m"
/* output log default color definition: [front color] + [background color] + [show style] */
#ifndef ELOG_COLOR_ASSERT
#define ELOG_COLOR_ASSERT (F_MAGENTA B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_ERROR
#define ELOG_COLOR_ERROR (F_RED B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_WARN
#define ELOG_COLOR_WARN (F_YELLOW B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_INFO
#define ELOG_COLOR_INFO (F_CYAN B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_DEBUG
#define ELOG_COLOR_DEBUG (F_GREEN B_NULL S_NORMAL)
#endif
#ifndef ELOG_COLOR_VERBOSE
#define ELOG_COLOR_VERBOSE (F_BLUE B_NULL S_NORMAL)
#endif
#endif /* ELOG_COLOR_ENABLE */

/* easy logger */
typedef struct {
    /* output log's filter */
    struct {
        uint8_t basic_lvl :7; /**< basic level filter for global, lower than tags filter */
        uint8_t enabled   :1; /**< false : filter is no used   true: filter is used */
#if defined(ELOG_FILTER_TAG_ENABLE) && (ELOG_FILTER_TAG_ENABLE != 0)
        struct {
            uint8_t level   :7;
            uint8_t enabled :1; /**< false : tag is no used   true: tag is used */
            char tag[ELOG_FILTER_TAG_MAX_LEN + 1];
        } tag_filters[ELOG_FILTER_TAG_MAX_NUM];
#endif /* ELOG_FILTER_TAG_ENABLE */
    } filter;

    size_t lvl_fmt[ELOG_FILTER_LVL_ALL + 1]; /**< output format for each level */
    bool init_ok                         :1;
    bool output_enabled                  :1;
    bool output_lock_enabled             :1;
    bool output_is_locked_before_enable  :1;
    bool output_is_locked_before_disable :1;
} EasyLogger;

/* EasyLogger object */
static EasyLogger elog;

/* every line log's buffer */
static char log_buf_normal[ELOG_LINE_BUF_SIZE] = { 0 };
#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
static char log_buf_isr[ELOG_LINE_BUF_SIZE] = { 0 };
#endif

/* level output info */
static const char *level_output_info[] = {
    [ELOG_LVL_ASSERT] = "A/",
    [ELOG_LVL_ERROR] = "E/",
    [ELOG_LVL_WARN] = "W/",
    [ELOG_LVL_INFO] = "I/",
    [ELOG_LVL_DEBUG] = "D/",
    [ELOG_LVL_VERBOSE] = "V/",
};

#if defined(ELOG_COLOR_ENABLE) && (ELOG_COLOR_ENABLE!= 0)
/* color output info */
static const char *color_output_info[] = {
    [ELOG_LVL_ASSERT] = ELOG_COLOR_ASSERT,
    [ELOG_LVL_ERROR] = ELOG_COLOR_ERROR,
    [ELOG_LVL_WARN] = ELOG_COLOR_WARN,
    [ELOG_LVL_INFO] = ELOG_COLOR_INFO,
    [ELOG_LVL_DEBUG] = ELOG_COLOR_DEBUG,
    [ELOG_LVL_VERBOSE] = ELOG_COLOR_VERBOSE,
};
#endif /* ELOG_COLOR_ENABLE */

/* EasyLogger assert hook */
void (*elog_assert_hook)(const char *expr, const char *func, size_t line);

extern void elog_console_output(bool in_isr, const char *log, size_t size);
extern void elog_backend_output(bool in_isr, uint32_t appender, uint8_t level,
                                const char *time, size_t time_len,
                                const char *info, size_t info_len,
                                const char *log, size_t log_len);
extern bool elog_port_output_lock(bool in_isr, uint32_t appender);
extern bool elog_port_output_unlock(bool in_isr, uint32_t appender);

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
#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
            elog_port_output_lock(in_isr, appender);
#else
            elog_port_output_lock(false, appender);
#endif /* ELOG_USING_IN_ISR */
        } else if (elog.output_is_locked_before_disable && !elog.output_is_locked_before_enable) {
            /* the output lock is locked before disable, and the lock will locking after enable */
#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
            elog_port_output_unlock(in_isr, appender);
#else
            elog_port_output_unlock(false, appender);
#endif /* ELOG_USING_IN_ISR */
        }
    }
}

ElogErrCode elog_output_lock(bool in_isr, uint32_t appender)
{
    if (elog.output_lock_enabled) {
#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
        if (elog_port_output_lock(in_isr, appender))
#else
        if (elog_port_output_lock(false, appender))
#endif /* ELOG_USING_IN_ISR */
        {
            elog.output_is_locked_before_disable = true;
            return ELOG_NO_ERR;
        }
        return ELOG_ELOCK_FAILED;
    }

    elog.output_is_locked_before_enable = true;
    return ELOG_NO_ERR;
}

ElogErrCode elog_output_unlock(bool in_isr, uint32_t appender)
{
    if (elog.output_lock_enabled) {
#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
        if (elog_port_output_unlock(in_isr, appender))
#else
        if (elog_port_output_unlock(false, appender))
#endif /* ELOG_USING_IN_ISR */
        {
            elog.output_is_locked_before_disable = false;
            return ELOG_NO_ERR;
        }
        return ELOG_ELOCK_FAILED;
    }

    elog.output_is_locked_before_enable = false;
    return ELOG_NO_ERR;
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

#if defined(ELOG_FILTER_TAG_ENABLE) && (ELOG_FILTER_TAG_ENABLE != 0)
ElogErrCode elog_set_filter_tag_lvl(const char *tag, uint8_t level)
{
    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);
    ELOG_ASSERT(tag != ((void *)0));
    uint8_t i = 0;
    ElogErrCode ret = ELOG_EFAILED;

    if (!elog.init_ok || !elog.filter.enabled) {
        return ELOG_EDENY;
    }

    if (ELOG_NO_ERR != elog_output_lock(false, ELOG_APD_ALL))
        return ELOG_ELOCK_FAILED;

    /* find the tag in arr */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        if (elog.filter.tag_filters[i].enabled &&
            !strncmp(tag, elog.filter.tag_filters[i].tag, ELOG_FILTER_TAG_MAX_LEN)) {
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
        ret = ELOG_NO_ERR;
    } else {
        /* only add the new tag's level filer when level is not ELOG_FILTER_LVL_ALL */
        if (level < ELOG_FILTER_LVL_ALL) {
            ret = ELOG_ENO_SPACE;
            for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
                if (!elog.filter.tag_filters[i].enabled) {
                    memset(elog.filter.tag_filters[i].tag, '\0', ELOG_FILTER_TAG_MAX_LEN + 1); //TODO: More efficient methods
                    strncpy(elog.filter.tag_filters[i].tag, tag, ELOG_FILTER_TAG_MAX_LEN);
                    elog.filter.tag_filters[i].level = level;
                    elog.filter.tag_filters[i].enabled = true;

                    ret = ELOG_NO_ERR;
                    break;
                }
            }
        }
    }

    if (ELOG_NO_ERR != elog_output_unlock(false, ELOG_APD_ALL))
        return ELOG_EUNLOCK_FAILED;

    return ret;
}

uint8_t elog_get_filter_tag_lvl(const char *tag)
{
    ELOG_ASSERT(tag != ((void *)0));
    uint8_t i = 0;
    uint8_t level = ELOG_FILTER_LVL_ALL;

    if (!elog.init_ok || !elog.filter.enabled) {
        return level;
    }

    if (ELOG_NO_ERR != elog_output_lock(false, ELOG_APD_ALL))
        return level;

    /* find the tag in arr */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        if (elog.filter.tag_filters[i].enabled == true &&
            !strncmp(tag, elog.filter.tag_filters[i].tag, ELOG_FILTER_TAG_MAX_LEN)) {
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

    ElogErrCode result = ELOG_NO_ERR;
    uint8_t i = 0;

    if (elog.init_ok == true) {
        return result;
    }

    /* port initialize */
    result = elog_port_init();
    if (result != ELOG_NO_ERR) {
        return result;
    }

#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
    result = elog_async_init();
    if (result != ELOG_NO_ERR) {
        return result;
    }
#endif

    /* enable the output lock */
    elog_output_lock_enabled(true, false, ELOG_APD_ALL);
    /* output locked status initialize */
    elog.output_is_locked_before_enable = false;
    elog.output_is_locked_before_disable = false;

    /* set basic level is ELOG_OUTPUT_LVL */
    elog_set_filter(ELOG_OUTPUT_LVL, true);

#if defined(ELOG_FILTER_TAG_ENABLE) && (ELOG_FILTER_TAG_ENABLE != 0)
    /* set tag_level to default val */
    for (i = 0; i < ELOG_FILTER_TAG_MAX_NUM; i++) {
        memset(elog.filter.tag_filters[i].tag, '\0', ELOG_FILTER_TAG_MAX_LEN + 1);
        elog.filter.tag_filters[i].level = ELOG_FILTER_LVL_SILENT;
        elog.filter.tag_filters[i].enabled = false;
    }
#endif /* ELOG_FILTER_TAG_ENABLE */

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

#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
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

#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
    elog_async_enabled(true);
#elif defined(ELOG_BUF_OUTPUT_ENABLE) && (ELOG_BUF_OUTPUT_ENABLE != 0)
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

#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
    elog_async_enabled(false);
#elif defined(ELOG_BUF_OUTPUT_ENABLE) && (ELOG_BUF_OUTPUT_ENABLE != 0)
    elog_buf_enabled(false);
#endif

    /* show version */
    LOG_I("EasyLogger V%s is deinitialize success.", ELOG_SW_VERSION);
}

void elog_raw_output(bool in_isr, uint32_t appender, const char *format, ...)
{
    va_list args;
    size_t log_len = 0;
    int fmt_result;
    char *log_buf = log_buf_normal;

    /* check output enabled */
    if (!elog.output_enabled) {
        return;
    }

    /* check output appender */
    if (!appender) {
        return;
    }

#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
    if (in_isr) {
        log_buf = log_buf_isr;
    }
#endif

    /* args point to the first variable parameter */
    va_start(args, format);

    /* lock output */
    if (ELOG_NO_ERR != elog_output_lock(in_isr, appender))
        return;

    /* package log data to buffer */
    fmt_result = vsnprintf(log_buf, ELOG_LINE_BUF_SIZE, format, args);

    /* output converted log */
    if ((fmt_result > -1) && (fmt_result <= ELOG_LINE_BUF_SIZE)) {
        log_len = fmt_result;
    } else {
        log_len = ELOG_LINE_BUF_SIZE;
    }
    /* output log */
#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
    extern void elog_async_output(uint8_t level, const char *log, size_t size);
    /* raw log will using assert level */
    elog_async_output(ELOG_LVL_ASSERT, log_buf, log_len);
#elif defined(ELOG_BUF_OUTPUT_ENABLE) && (ELOG_BUF_OUTPUT_ENABLE != 0)
    extern void elog_buf_output(const char *log, size_t size);
    elog_buf_output(log_buf, log_len);
#else
    if (appender & ELOG_APD_CONSOLE)
        elog_console_output(in_isr, log_buf, log_len);

    if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
        elog_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), ELOG_LVL_DEBUG,
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

    size_t newline_len = strlen(ELOG_NEWLINE_SIGN), level_format = elog.lvl_fmt[level], log_len = 0, tag_len, time_len, fmt_info_len, raw_log_len;
    char line_num[ELOG_FMT_LINE_MAX_LEN + 1] = { 0 };
    char tag_sapce[ELOG_FILTER_TAG_MAX_LEN / 2 + 1] = { 0 };
    char *log_buf = log_buf_normal, *file_name = NULL, *time_addr = NULL, *fmt_info_addr = NULL, *raw_log_addr = NULL;
    int fmt_result;
    uint8_t tag_level = ELOG_LVL_VERBOSE;
    va_list args;

    ELOG_ASSERT(level <= ELOG_LVL_VERBOSE);

    /* check output enabled */
    if (!elog.output_enabled) {
        return;
    }

    /* check output appender */
    if (!appender) {
        return;
    }

    /* level filter */
    if (elog.filter.enabled) {
#if defined(ELOG_FILTER_TAG_ENABLE) && (ELOG_FILTER_TAG_ENABLE != 0)
        tag_level = elog_get_filter_tag_lvl(tag);
        if (tag_level < ELOG_LVL_VERBOSE) {
            if (level > tag_level)
                return;
        } else
#endif /* ELOG_FILTER_TAG_ENABLE */
        {
            if (level > elog.filter.basic_lvl) {
                return;
            }
        }
    }

    /* lock output */
    if (ELOG_NO_ERR != elog_output_lock(in_isr, appender)) {
        return;
    }

#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
    if (in_isr) {
        log_buf = log_buf_isr;
    }
#endif

    /* args point to the first variable parameter */
    va_start(args, format);

#if defined(ELOG_COLOR_ENABLE) && (ELOG_COLOR_ENABLE!= 0)
    /* add CSI start sign and color info */
    log_len += elog_strcpy(log_len, log_buf + log_len, CSI_START);
    log_len += elog_strcpy(log_len, log_buf + log_len, color_output_info[level]);
#endif

    /* package time */
    if (level_format & ELOG_FMT_TIME) {
        log_len += elog_strcpy(log_len, log_buf + log_len, "[");
        time_addr = log_buf + log_len;
        time_len = elog_strcpy(log_len, time_addr, elog_port_get_time());
        log_len += time_len;
        log_len += elog_strcpy(log_len, log_buf + log_len, "] ");
    }

    /* record the fmt info addr */
    fmt_info_addr = log_buf + log_len;
    /* package level info */
    if (level_format & ELOG_FMT_LVL) {
        log_len += elog_strcpy(log_len, log_buf + log_len, level_output_info[level]);
    }

    /* package tag info */
    if (level_format & ELOG_FMT_TAG) {
        tag_len = strlen(tag);
        log_len += elog_strcpy(log_len, log_buf + log_len, tag);
        /* if the tag length is less than 50% ELOG_FILTER_TAG_MAX_LEN, then fill space */
        if (tag_len <= ELOG_FILTER_TAG_MAX_LEN / 2) {
            memset(tag_sapce, ' ', ELOG_FILTER_TAG_MAX_LEN / 2 - tag_len);
            log_len += elog_strcpy(log_len, log_buf + log_len, tag_sapce);
        }
    }

    /* package process and thread info */
    if (level_format & (ELOG_FMT_P_INFO | ELOG_FMT_T_INFO)) {
        log_len += elog_strcpy(log_len, log_buf + log_len, "[");
        /* package process info */
        if (level_format & ELOG_FMT_P_INFO) {
            log_len += elog_strcpy(log_len, log_buf + log_len, "p(");
            log_len += elog_strcpy(log_len, log_buf + log_len, elog_port_get_p_info());

            if (level_format & ELOG_FMT_T_INFO)
                log_len += elog_strcpy(log_len, log_buf + log_len, ") ");
            else
                log_len += elog_strcpy(log_len, log_buf + log_len, ")");
        }
        /* package thread info */
        if (level_format & ELOG_FMT_T_INFO) {
            log_len += elog_strcpy(log_len, log_buf + log_len, "t(");
            log_len += elog_strcpy(log_len, log_buf + log_len, elog_port_get_t_info());
            log_len += elog_strcpy(log_len, log_buf + log_len, ")");
        }
        log_len += elog_strcpy(log_len, log_buf + log_len, "] ");
    }

    /* package file directory and name, function name and line number info */
    if (level_format & (ELOG_FMT_DIR | ELOG_FMT_NAME | ELOG_FMT_FUNC)) {
        log_len += elog_strcpy(log_len, log_buf + log_len, "[");
        /* package file info */
        if (level_format & ELOG_FMT_DIR) {
            log_len += elog_strcpy(log_len, log_buf + log_len, file);
        } else if (level_format & ELOG_FMT_NAME) {
            /* get file name */
            file_name = strrchr(file, '\\');    // windows
            if (file_name == NULL)
                file_name = strrchr(file, '/'); // linux

            if (file_name == NULL)
                file_name = (char *)file;
            else
                file_name++;

            log_len += elog_strcpy(log_len, log_buf + log_len, (const char *)file_name);
        }
        /* package func info */
        if (level_format & ELOG_FMT_FUNC) {
            log_len += elog_strcpy(log_len, log_buf + log_len, ":");
            log_len += elog_strcpy(log_len, log_buf + log_len, func);
        }
        /* package line info */
        log_len += elog_strcpy(log_len, log_buf + log_len, "(");
        snprintf(line_num, ELOG_FMT_LINE_MAX_LEN, "%ld", line);
        log_len += elog_strcpy(log_len, log_buf + log_len, line_num);
        log_len += elog_strcpy(log_len, log_buf + log_len, ")]");
    }

    /* reacquire the fmt info addr and fmt info len */
    if ((log_buf + log_len) == fmt_info_addr) {
        fmt_info_addr = NULL;
        fmt_info_len = 0;
    } else {
        fmt_info_len = log_buf + log_len - fmt_info_addr;
    }

    /* package other log data to buffer. '\0' must be added in the end by vsnprintf. */
    log_len += elog_strcpy(log_len, log_buf + log_len, ": ");
    raw_log_addr = log_buf + log_len;
    fmt_result = vsnprintf(raw_log_addr, ELOG_LINE_BUF_SIZE - log_len, format, args);

    va_end(args);
    /* calculate log length */
    if ((log_len + fmt_result <= ELOG_LINE_BUF_SIZE) && (fmt_result > -1)) {
        log_len += fmt_result;
    } else {
        /* using max length */
        log_len = ELOG_LINE_BUF_SIZE;
    }
    /* overflow check and reserve some space for CSI end sign and newline sign */
#if defined(ELOG_COLOR_ENABLE) && (ELOG_COLOR_ENABLE!= 0)
    if (log_len + (sizeof(CSI_END) - 1) + newline_len > ELOG_LINE_BUF_SIZE) {
        /* using max length */
        log_len = ELOG_LINE_BUF_SIZE;
        /* reserve some space for CSI end sign */
        log_len -= (sizeof(CSI_END) - 1);
        /* reserve some space for newline sign */
        log_len -= newline_len;
    }
#else
    if (log_len + newline_len > ELOG_LINE_BUF_SIZE) {
        /* using max length */
        log_len = ELOG_LINE_BUF_SIZE;
        /* reserve some space for newline sign */
        log_len -= newline_len;
    }
#endif /* ELOG_COLOR_ENABLE */

    /* reacquire the raw log addr and raw log len */
    if ((log_buf + log_len) == raw_log_addr) {
        raw_log_addr = NULL;
        raw_log_len = 0;
    } else {
        raw_log_len = log_buf + log_len - raw_log_addr;
    }

#if defined(ELOG_COLOR_ENABLE) && (ELOG_COLOR_ENABLE!= 0)
    /* add CSI end sign */
    log_len += elog_strcpy(log_len, log_buf + log_len, CSI_END);
#endif
    /* package newline sign */
    log_len += elog_strcpy(log_len, log_buf + log_len, ELOG_NEWLINE_SIGN);

    /* output log */
#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
    extern void elog_async_output(uint8_t level, const char *log, size_t size);
    elog_async_output(level, log_buf, log_len);
#elif defined(ELOG_BUF_OUTPUT_ENABLE) && (ELOG_BUF_OUTPUT_ENABLE != 0)
    extern void elog_buf_output(const char *log, size_t size);
    elog_buf_output(log_buf, log_len);
#else
    if (appender & ELOG_APD_CONSOLE)
        elog_console_output(in_isr, log_buf, log_len);

    if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
        elog_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), level,
                            time_addr, time_len,
                            fmt_info_addr, fmt_info_len,
                            raw_log_addr, raw_log_len);
#endif
    /* unlock output */
    elog_output_unlock(in_isr, appender);
}

void elog_hexdump(bool in_isr, uint32_t appender, const char *name, uint8_t width, const void *buf, uint16_t size)
{
#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

    uint16_t i, j;
    uint16_t log_len = 0;
    const uint8_t *buf_p = buf;
    char *log_buf = log_buf_normal, dump_string[8] = { 0 };
    int fmt_result;

    if (!elog.output_enabled) {
        return;
    }

    /* check output appender */
    if (!appender) {
        return;
    }

    /* level filter */
    if (elog.filter.enabled && (ELOG_LVL_DEBUG > elog.filter.basic_lvl)) {
        return;
    }

#if defined(ELOG_USING_IN_ISR) && (ELOG_USING_IN_ISR != 0)
    if (in_isr) {
        log_buf = log_buf_isr;
    }
#endif

    /* lock output */
    if (ELOG_NO_ERR != elog_output_lock(in_isr, appender)) {
        return;
    }

    for (i = 0; i < size; i += width) {
        /* package header */
        fmt_result = snprintf(log_buf, ELOG_LINE_BUF_SIZE, "D/HEX %s: %04X-%04X: ", name, i, i + width - 1);
        /* calculate log length */
        if ((fmt_result > -1) && (fmt_result <= ELOG_LINE_BUF_SIZE)) {
            log_len = fmt_result;
        } else {
            log_len = ELOG_LINE_BUF_SIZE;
        }
        /* dump hex */
        for (j = 0; j < width; j++) {
            if (i + j < size) {
                snprintf(dump_string, sizeof(dump_string), "%02X ", buf_p[i + j]);
            } else {
                strncpy(dump_string, "   ", sizeof(dump_string));
            }
            log_len += elog_strcpy(log_len, log_buf + log_len, dump_string);
            if ((j + 1) % 8 == 0) {
                log_len += elog_strcpy(log_len, log_buf + log_len, " ");
            }
        }
        log_len += elog_strcpy(log_len, log_buf + log_len, "  ");
        /* dump char for hex */
        for (j = 0; j < width; j++) {
            if (i + j < size) {
                snprintf(dump_string, sizeof(dump_string), "%c", __is_print(buf_p[i + j]) ? buf_p[i + j] : '.');
                log_len += elog_strcpy(log_len, log_buf + log_len, dump_string);
            }
        }
        /* overflow check and reserve some space for newline sign */
        if (log_len + strlen(ELOG_NEWLINE_SIGN) > ELOG_LINE_BUF_SIZE) {
            log_len = ELOG_LINE_BUF_SIZE - strlen(ELOG_NEWLINE_SIGN);
        }
        /* package newline sign */
        log_len += elog_strcpy(log_len, log_buf + log_len, ELOG_NEWLINE_SIGN);
        /* do log output */
#if defined(ELOG_ASYNC_OUTPUT_ENABLE) && (ELOG_ASYNC_OUTPUT_ENABLE != 0)
        extern void elog_async_output(uint8_t level, const char *log, size_t size);
        elog_async_output(ELOG_LVL_DEBUG, log_buf, log_len);
#elif defined(ELOG_BUF_OUTPUT_ENABLE) && (ELOG_BUF_OUTPUT_ENABLE != 0)
        extern void elog_buf_output(const char *log, size_t size);
        elog_buf_output(log_buf, log_len);
#else
        if (appender & ELOG_APD_CONSOLE)
            elog_console_output(in_isr, log_buf, log_len);

        if ((appender & ELOG_APD_CONSOLE) != ELOG_APD_CONSOLE)
            elog_backend_output(in_isr, appender & (~ELOG_APD_CONSOLE), ELOG_LVL_DEBUG,
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
