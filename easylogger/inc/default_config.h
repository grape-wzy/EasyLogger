/*
 * This file is part of the EasyLogger Library.
 *
 * Copyright (c) 2015-2016, Armink, <armink.ztl@gmail.com>
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
 * Function: It is the configure head file for this library.
 * Created on: 2015-07-30
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_
/*---------------------------------------------------------------------------*/
/* enable log output. */
#define ELOG_OUTPUT_ENABLE                          1
/* setting static output log level. range: from ELOG_LVL_ASSERT to ELOG_LVL_VERBOSE */
#define ELOG_OUTPUT_LVL                             ELOG_LVL_VERBOSE
/* enable assert check */
#define ELOG_ASSERT_ENABLE                          0
/* enable the isr environment support */
#define ELOG_USING_IN_ISR                           0
/* enable log filter's tag support. Tag's filter level is higher than basic level */
#define ELOG_FILTER_TAG_ENABLE                      1
/* enable the directory support in log format. Enable this feature will automatically enable the ELOG_FMT_NAME_ENABLE */
#define ELOG_FMT_DIR_ENABLE                         0
/* enable the file name support in log format */
#define ELOG_FMT_NAME_ENABLE                        0
/* enable the function name support in log format */
#define ELOG_FMT_FUNC_ENABLE                        0
/* buffer size for every line's log */
#define ELOG_OUTPUT_BUF_SIZE                        256
/* output filter's tag max length */
#define ELOG_FILTER_TAG_MAX_LEN                     30
/* output filter's tag max num */
#define ELOG_FILTER_TAG_MAX_NUM                     5
/* output newline sign */
#define ELOG_NEWLINE_SIGN                           "\n"
/*---------------------------------------------------------------------------*/
/* enable log color */
#define ELOG_COLOR_ENABLE                           1
/* change the some level logs to not default color if you want */
#define ELOG_COLOR_ASSERT                           (F_MAGENTA B_NULL S_NORMAL)
#define ELOG_COLOR_ERROR                            (F_RED B_NULL S_NORMAL)
#define ELOG_COLOR_WARN                             (F_YELLOW B_NULL S_NORMAL)
#define ELOG_COLOR_INFO                             (F_CYAN B_NULL S_NORMAL)
#define ELOG_COLOR_DEBUG                            (F_GREEN B_NULL S_NORMAL)
#define ELOG_COLOR_VERBOSE                          (F_BLUE B_NULL S_NORMAL)
/*---------------------------------------------------------------------------*/
/* enable asynchronous output mode */
#define ELOG_ASYNC_OUTPUT_ENABLE                    0
/* the highest output level for async mode, other level will sync output */
#define ELOG_ASYNC_OUTPUT_LVL                       ELOG_LVL_ASSERT
/* buffer size for asynchronous output mode */
#define ELOG_ASYNC_OUTPUT_BUF_SIZE                  (ELOG_OUTPUT_BUF_SIZE * 10)
/* each asynchronous output's log which must end with newline sign */
#define ELOG_ASYNC_LINE_OUTPUT                      0
/* asynchronous output mode using POSIX pthread implementation */
#define ELOG_ASYNC_OUTPUT_USING_PTHREAD             0
/*---------------------------------------------------------------------------*/
/* enable buffered output mode */
#define ELOG_BUF_OUTPUT_ENABLE                      0
/* buffer size for buffered output mode */
#define ELOG_BUF_OUTPUT_BUF_SIZE                    (ELOG_OUTPUT_BUF_SIZE * 10)

/**
 * @brief All the log append.
 * @note Define your own log append between "ELOG_APD_CONSOLE" and "ELOG_APD_ALL" with shift,
 *      and the arguments will be passed to the elog_port_backend_output() function.
 * @note Multiple output containers can be specified the '|' operator.
 * @example
 *          ELOG_APD_BACKEND_FLASH = (1 << 2),
 *          ELOG_APD_BACKEND_FILE  = (1 << 3),
 */
typedef enum {
    ELOG_APD_CONSOLE = (1 << 0), /**< log will output to console */
    /* USER CODE BEGIN ElogApdIndex */

    /* USER CODE END ElogApdIndex */
    ELOG_APD_ALL = 0xFFFFFFFF,
} ElogApdIndex;

#endif /* _CONFIG_H_ */
