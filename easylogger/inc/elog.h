/*
 * This file is part of the EasyLogger Library.
 *
 * Copyright (c) 2015-2019, Armink, <armink.ztl@gmail.com>
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
 * Function: It is an head file for this library. You can see all be called functions.
 * Created on: 2015-04-28
 */

#ifndef __ELOG_H__
#define __ELOG_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __has_include
#if __has_include("elog_cfg.h")
#include "elog_cfg.h"
#else
#include "default_config.h"
#warning ""elog_cfg" is not found, use "default_config.h"."
#endif
#else
#include "elog_cfg.h"
#warning "The pre compiled macro "__has_include" is not supported, please refer to the "default_config.h" to configure your "elog_cfg.h"."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* output log's level.
 *
 * ELOG_LVL_ASSERT is the highest level.
 *
 */
#define ELOG_LVL_ASSERT                                     0
#define ELOG_LVL_ERROR                                      1
#define ELOG_LVL_WARN                                       2
#define ELOG_LVL_INFO                                       3
#define ELOG_LVL_DEBUG                                      4
#define ELOG_LVL_VERBOSE                                    5

/* the output silent level and all level for filter setting */
#define ELOG_FILTER_LVL_SILENT                              ELOG_LVL_ASSERT
#define ELOG_FILTER_LVL_ALL                                 ELOG_LVL_VERBOSE

/* EasyLogger software version number */
#define ELOG_SW_VERSION                                     "2.2.99"

#if ELOG_FMT_DIR_ENABLE
#undef ELOG_FMT_NAME_ENABLE
#define ELOG_FMT_NAME_ENABLE                                0
#define ELOG_FILE_DIR                                       __FILE__
#ifndef DIR_NAME_FUNC_FLAG
#define DIR_NAME_FUNC_FLAG
#endif /* DIR_NAME_FUNC_FLAG */
#elif ELOG_FMT_NAME_ENABLE
#define ELOG_FILE_DIR                                       __FILE__
#ifndef DIR_NAME_FUNC_FLAG
#define DIR_NAME_FUNC_FLAG
#endif /* DIR_NAME_FUNC_FLAG */
#else
#define ELOG_FILE_DIR                                       "\0"
#endif

#if ELOG_FMT_FUNC_ENABLE
#define ELOG_FUNC_NAME                                      __FUNCTION__
#ifndef DIR_NAME_FUNC_FLAG
#define DIR_NAME_FUNC_FLAG
#endif /* DIR_NAME_FUNC_FLAG */
#else
#define ELOG_FUNC_NAME                                      "\0"
#endif

#if defined(ELOG_OUTPUT_BUF_SIZE) && (ELOG_OUTPUT_BUF_SIZE < 64)
#warning "It is not recommended to set the output buffer too small as it will increase the time cost of log output"
#undef ELOG_OUTPUT_BUF_SIZE
#define ELOG_OUTPUT_BUF_SIZE                                64
#endif

#if ELOG_OUTPUT_ENABLE
#if ELOG_OUTPUT_LVL >= ELOG_LVL_ASSERT
#define elog_assert(in_isr, appender, tag, ...)             elog_output(in_isr, appender, ELOG_LVL_ASSERT, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_assert(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_ASSERT */
#if ELOG_OUTPUT_LVL >= ELOG_LVL_ERROR
#define elog_error(in_isr, appender, tag, ...)              elog_output(in_isr, appender, ELOG_LVL_ERROR, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_error(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_ERROR */
#if ELOG_OUTPUT_LVL >= ELOG_LVL_WARN
#define elog_warn(in_isr, appender, tag, ...)               elog_output(in_isr, appender, ELOG_LVL_WARN, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_warn(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_WARN */
#if ELOG_OUTPUT_LVL >= ELOG_LVL_INFO
#define elog_info(in_isr, appender, tag, ...)               elog_output(in_isr, appender, ELOG_LVL_INFO, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_info(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_INFO */
#if ELOG_OUTPUT_LVL >= ELOG_LVL_DEBUG
#define elog_debug(in_isr, appender, tag, ...)              elog_output(in_isr, appender, ELOG_LVL_DEBUG, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_debug(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_DEBUG */
#if ELOG_OUTPUT_LVL == ELOG_LVL_VERBOSE
#define elog_verbose(in_isr, appender, tag, ...)            elog_output(in_isr, appender, ELOG_LVL_VERBOSE, tag, ELOG_FILE_DIR, ELOG_FUNC_NAME, __LINE__, __VA_ARGS__)
#else
#define elog_verbose(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_LVL == ELOG_LVL_VERBOSE */
#if ELOG_OUTPUT_LVL >= ELOG_LVL_DEBUG
#define elog_hex(in_isr, appender, tag, width, buf, size)   elog_hexdump(in_isr, appender, tag, width, buf, size)
#else
#define elog_hex(in_isr, appender, tag, width, buf, size)
#endif /* ELOG_OUTPUT_LVL >= ELOG_LVL_DEBUG */
#define elog_raw(in_isr, appender, ...)                     elog_raw_output(in_isr, appender, __VA_ARGS__)
#else /* ELOG_OUTPUT_ENABLE */
#define elog_hex(in_isr, appender, tag, width, buf, size)
#define elog_raw(in_isr, appender, ...)
#define elog_assert(in_isr, appender, tag, ...)
#define elog_error(in_isr, appender, tag, ...)
#define elog_warn(in_isr, appender, tag, ...)
#define elog_info(in_isr, appender, tag, ...)
#define elog_debug(in_isr, appender, tag, ...)
#define elog_verbose(in_isr, appender, tag, ...)
#endif /* ELOG_OUTPUT_ENABLE */

#if !defined(LOG_TAG)
#define LOG_TAG                                             "NO_TAG"
#endif
#if !defined(LOG_LVL)
#define LOG_LVL                                             ELOG_OUTPUT_LVL
#endif
#if !defined(LOG_IN_ISR)
#define LOG_IN_ISR                                          false
#endif
#if !defined(LOG_APPENDER)
#define LOG_APPENDER                                        ELOG_APD_CONSOLE
#endif

/**
 * log API short definition
 * NOTE: The `LOG_TAG` and `LOG_LVL` must defined before including the <elog.h> when you want to use log_x API.
 */
#if LOG_LVL >= ELOG_LVL_ERROR
#define LOG_E(...)                                          elog_error(LOG_IN_ISR, LOG_APPENDER, LOG_TAG, __VA_ARGS__)
#else
#define LOG_E(...)
#endif
#if LOG_LVL >= ELOG_LVL_WARN
#define LOG_W(...)                                          elog_warn(LOG_IN_ISR, LOG_APPENDER, LOG_TAG, __VA_ARGS__)
#else
#define LOG_W(...)
#endif
#if LOG_LVL >= ELOG_LVL_INFO
#define LOG_I(...)                                          elog_info(LOG_IN_ISR, LOG_APPENDER, LOG_TAG, __VA_ARGS__)
#else
#define LOG_I(...)
#endif
#if LOG_LVL >= ELOG_LVL_DEBUG
#define LOG_D(...)                                          elog_debug(LOG_IN_ISR, LOG_APPENDER, LOG_TAG, __VA_ARGS__)
#define LOG_HEX(tag, width, buf, size)                      elog_hex(LOG_IN_ISR, LOG_APPENDER, tag, width, buf, size)
#define LOG_RAW(...)                                        elog_raw(LOG_IN_ISR, LOG_APPENDER, __VA_ARGS__)
#else
#define LOG_D(...)
#define LOG_HEX(tag, width, buf, size)
#define LOG_RAW(...)
#endif
#if LOG_LVL >= ELOG_LVL_VERBOSE
#define LOG_V(...)                                          elog_verbose(LOG_IN_ISR, LOG_APPENDER, LOG_TAG, __VA_ARGS__)
#else
#define LOG_V(...)
#endif

/* EasyLogger assert for developer. */
#if defined(ELOG_ASSERT_ENABLE) && (ELOG_ASSERT_ENABLE != 0)
#define ELOG_ASSERT(EXPR)                                           \
    if (!(EXPR)) {                                                  \
        if (elog_assert_hook == NULL) {                             \
            elog_assert(false, ELOG_APD_CONSOLE, "elog.assert",     \
                        "(%s) has assert failed at %s:%ld.", #EXPR, \
                        ELOG_FUNC_NAME, __LINE__);                  \
            while (1) {}                                            \
        } else {                                                    \
            elog_assert_hook(#EXPR, ELOG_FUNC_NAME, __LINE__);      \
        }                                                           \
    }
#else
#define ELOG_ASSERT(EXPR)
#endif

/* all formats index */
typedef enum {
    ELOG_FMT_TIME   = (1 << 0), /**< current time */
    ELOG_FMT_LVL    = (1 << 1), /**< level */
    ELOG_FMT_TAG    = (1 << 2), /**< tag */
    ELOG_FMT_P_INFO = (1 << 3), /**< process info */
    ELOG_FMT_T_INFO = (1 << 4), /**< thread info */
    ELOG_FMT_DIR    = (1 << 5), /**< file directory and name */
    ELOG_FMT_NAME   = (1 << 6), /**< file name */
    ELOG_FMT_FUNC   = (1 << 7), /**< function name */
} ElogFmtIndex;

/* EasyLogger error code */
typedef enum {
    ELOG_EOK = 0,        /**< no error */
    ELOG_EFAILED,        /**< failure code */
    ELOG_EDENY,          /**< Operation be denied */
    ELOG_ENO_SPACE,      /**< no space in tag filter array */
    ELOG_ELOCK_FAILED,   /**< lock the output failed */
    ELOG_EUNLOCK_FAILED, /**< unlock the output failed */
} ElogErrCode;

/* function in elog.c */
#if ELOG_OUTPUT_ENABLE
/**
 * @brief set output enable or disable
 *
 * @param enabled true: enable false: disable
 */
void elog_set_output_enabled(bool enabled);

/**
 * @brief get output is enable or disable
 *
 * @return enable or disable
 */
bool elog_get_output_enabled(void);

/**
 * @brief enable or disable logger output lock
 *
 * @note disable this lock is not recommended except you want output system exception log
 *
 * @param enabled true: enable  false: disable.
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the appender need to be lock.
 */
void elog_output_lock_enabled(bool enabled, bool in_isr, uint32_t appender);

/**
 * @brief lock output, just used by elog
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the appender need to be lock.
 *
 * @return ELOG_EOK or ELOG_ELOCK_FAILED
 */
ElogErrCode elog_output_lock(bool in_isr, uint32_t appender);

/**
 * @brief unlock output, just used by elog
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the appender need to be unlock.
 *
 * @return ELOG_EOK or ELOG_ELOCK_FAILED
 */
ElogErrCode elog_output_unlock(bool in_isr, uint32_t appender);

/**
 * @brief set log output format for specified log level.
 *
 * @param level specified log level
 * @param format the format you want to set
 */
void elog_set_fmt(uint8_t level, size_t format);

/**
 * @brief set log filter.
 *
 * @param basic_level the basic level of log filter.
 * @param enabled true: enable,  false: disable
 *
 * @note This level is only effective when the tag filter "ELOG_FILTER_TAG_ENABLE" is not enabled or
 *   the tag is not in the filter or the tag is be set to ELOG_FILTER_LVL_ALL.
 */
void elog_set_filter(uint8_t basic_level, bool enabled);

#if ELOG_FILTER_TAG_ENABLE
/**
 * @brief Set the filter's level by different tag.
 * All logs below this level under this tag will be refused to output, and the log under this tag will no
 * longer be limited by the basic level which set by function: elog_set_filter(uint8_t basic_level, bool enabled).
 *
 * @example: the example tag log enter silent mode:
 *     elog_set_filter_tag_lvl("example", ELOG_FILTER_LVL_SILENT);
 * @example: the example tag log which level is less than INFO level will stop output:
 *     elog_set_filter_tag_lvl("example", ELOG_LVL_INFO);
 * @example: remove example tag's level filter, all level log will resume output:
 *     elog_set_filter_tag_lvl("example", ELOG_FILTER_LVL_ALL);
 *
 * @param tag log tag
 * @param level The filter level. When the level is ELOG_FILTER_LVL_SILENT, the log enter silent mode.
 *        When the level is ELOG_FILTER_LVL_ALL, it will remove this tag's level filer.
 *        Then all level log will resume output.
 *
 * @return reference to ElogErrCode.
 *
 * @note can not be called in interrupt environments.
 */
ElogErrCode elog_set_filter_tag(const char *tag, uint8_t level);

/**
 * @brief get the level on tag's level filer
 *
 * @param tag tag

 * @return It will return the lowest level(ELOG_LVL_VERBOSE) when tag was not found.
 *         Other level will return when tag was found.
 *
 * @note can not be called in interrupt environments.
 */
uint8_t elog_get_filter_tag_lvl(const char *tag);
#endif /* ELOG_FILTER_TAG_ENABLE */

/**
 * @brief Set a hook function to EasyLogger assert. It will run when the expression is false.
 *
 * @param hook the hook function
 */
void elog_assert_set_hook(void (*hook)(const char *expr, const char *func, size_t line));

/**
 * @brief EasyLogger initialize.
 *
 * @return result
 *
 * @note can not be called in interrupt environments.
 */
ElogErrCode elog_init(void);

/**
 * @brief EasyLogger deinitialize.
 *
 */
void elog_deinit(void);

/**
 * @brief EasyLogger start after initialize.
 */
void elog_start(void);

/**
 * @brief EasyLogger stop after initialize.
 */
void elog_stop(void);

/**
 * @brief output RAW format log
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender appender
 * @param format output format
 * @param ... args
 */
void elog_raw_output(bool in_isr, uint32_t appender, const char *format, ...);

/**
 * @brief output the log, full type is: [time] I/tag[p:p_info t:t_info][.\dir\filename.c:line function]: your raw log.
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender appender
 * @param level level
 * @param tag tag
 * @param file file name
 * @param func function name
 * @param line line number
 * @param format output format
 * @param ... args
 */
void elog_output(bool in_isr, uint32_t appender, uint8_t level,
                 const char *tag, const char *file, const char *func, const long line,
                 const char *format, ...);

/**
 * @brief dump the hex format data to log
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender appender
 * @param name name for hex object, it will show on log header
 * @param width hex number for every line, such as: 16, 32
 * @param buf hex buffer
 * @param size buffer size
 */
void elog_hexdump(bool in_isr, uint32_t appender, const char *name, uint8_t width, const void *buf, uint16_t size);
#endif /* ELOG_OUTPUT_ENABLE */

#ifdef __cplusplus
}
#endif

#endif /* __ELOG_H__ */
