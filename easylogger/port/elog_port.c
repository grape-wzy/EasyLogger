/*
 * This file is part of the EasyLogger Library.
 *
 * Copyright (c) 2015, Armink, <armink.ztl@gmail.com>
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
 * Function: Portable interface for each platform.
 * Created on: 2015-04-28
 */

#include <elog.h>

/**
 * @brief EasyLogger port initialize
 *
 * @return result
 */
ElogErrCode elog_port_init(void)
{
    ElogErrCode result = ELOG_NO_ERR;

    /* add your code here */

    return result;
}

/**
 * @brief EasyLogger port deinitialize

 */
void elog_port_deinit(void)
{
    /* add your code here */
}

/**
 * @brief output log to console
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param log output of log
 *
 * @param size log size
 */
void elog_console_output(bool in_isr, const char *log, size_t size)
{
    /* add your code here */
}

/**
 * @brief output log to others appender, such as file, flash, etc...
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the others appenders, defined in ElogApdIndex @elog_cfg.h file
 * @param level log's level
 * @param time time in string format
 * @param time_len length of time string
 * @param info the format information in log,
 *          maybe include level string, tag, process information, thread information, directory information, line information, etc...
 * @param info_len information length
 * @param log the raw log message
 * @param log_len length of raw log message
 *
 * @note If the time's/info's/log's len equals to 0 or addr pointer is NULL, meaning that the message is not present in this log.
 */
void elog_backend_output(bool in_isr, uint32_t appender, uint8_t level,
                         const char *time, size_t time_len,
                         const char *info, size_t info_len,
                         const char *log, size_t log_len)
{
    /* add your code here */
}

/**
 * @brief port output lock
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the appender need to be lock.
 *
 * @return true means success operation, otherwise it will failed
 */
bool elog_port_lock(bool in_isr, uint32_t appender)
{
    bool result = true;

    /* add your code here */

    return result;
}

/**
 * @brief port output unlock
 *
 * @param in_isr called environment. true: called in interrupt, false: called normally.
 * @param appender the appender need to be unlock.
 *
 * @return true means success operation, otherwise it will failed
 */
bool elog_port_unlock(bool in_isr, uint32_t appender)
{
    bool result = true;

    /* add your code here */

    return result;
}

/**
 * @brief get current time interface
 *
 * @return current time in string format
 */
const char *elog_port_get_time(void)
{
    /* add your code here */
}

/**
 * @brief get current process name interface
 *
 * @return current process name
 */
const char *elog_port_get_p_info(void)
{
    /* add your code here */
}

/**
 * @brief get current thread name interface
 *
 * @return current thread name
 */
const char *elog_port_get_t_info(void)
{
    /* add your code here */
}
