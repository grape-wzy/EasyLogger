
/*
 * Following implementation is adapted from original one
 *   https://github.com/jpbonn/coremark_lm32/blob/master/ee_printf.c
 */

#define ELOG_USE_TINY_PRINTF 1

#if defined(ELOG_USE_TINY_PRINTF) && (ELOG_USE_TINY_PRINTF != 0)

#include <stdarg.h>
#include <stddef.h>

// #define TINY_PRINTF
#define HAS_FLOAT

#define ZEROPAD             (1 << 0) /* Pad with zero */
#define SIGN                (1 << 1) /* Unsigned/signed long */
#ifndef TINY_PRINTF
#define PLUS                (1 << 2) /* Show plus */
#define SPACE               (1 << 3) /* Spacer */
#define LEFT                (1 << 4) /* Left justified */
#define HEX_PREP            (1 << 5) /* 0x */
#endif
#define UPPERCASE           (1 << 6) /* 'ABCDEF' */

#define is_digit(c)         ((c) >= '0' && (c) <= '9')

#define GADGET_INITIALIZED  { NULL, NULL, NULL, 0, 0}

/* _vsp_inline Definitions */
#if defined(__ARMCC_VERSION)        /* ARM Compiler */
#define _vsp_inline                                          static __inline
#elif defined (__IAR_SYSTEMS_ICC__) /* for IAR Compiler */
#define _vsp_inline                                          static inline
#elif defined (__GNUC__)            /* GNU GCC Compiler */
#define _vsp_inline                                          static __inline
#elif defined (__ADSPBLACKFIN__)    /* for VisualDSP++ Compiler */
#define _vsp_inline                                          static inline
#elif defined (_MSC_VER)
#define _vsp_inline                                          static __inline
#elif defined (__TI_COMPILER_VERSION__)
#define _vsp_inline                                          static inline
#elif defined (__TASKING__)
#define _vsp_inline                                          static inline
#else
    #error not supported tool chain
#endif /* __ARMCC_VERSION */

// wrapper (used as buffer) for output function type
//
// One of the following must hold:
// 1. max_chars is 0
// 2. buffer is non-null
// 3. function is non-null
//
// ... otherwise bad things will happen.
typedef struct {
    void (*function)(char c, void *extra_arg);
    void *extra_function_arg;
    char *buffer;
    size_t pos;
    size_t buff_size;
} output_gadget_t;

static char *lower_digits = "0123456789abcdefghijklmnopqrstuvwxyz";
static char *upper_digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Note: This function currently assumes it is not passed a '\0' c,
// or alternatively, that '\0' can be passed to the function in the output
// gadget. The former assumption holds within the printf library. It also
// assumes that the output gadget has been properly initialized.
// Note: If the buffer is fully, the function will return 1.
_vsp_inline char putchar_via_gadget(output_gadget_t *gadget, char c)
{
    gadget->pos++;
    // We're _always_ increasing pos, so as to count how may characters
    // _would_ have been written if not for the buff_size limitation
    if (gadget->function) {
        gadget->function(c, gadget->extra_function_arg); // No check for c == '\0' .
    } else if (gadget->pos > gadget->buff_size) {
        return 1;
    } else {
        // it must be the case that gadget->buffer != NULL , due to the constraint
        // on output_gadget_t ; and note we're relying on write_pos being non-negative.
        gadget->buffer[gadget->pos - 1] = c;
    }
    return 0;
}

#ifndef TINY_PRINTF
static size_t strnlen(const char *s, size_t count)
{
    const char *sc;
    for (sc = s; *sc != '\0' && count--; ++sc) ;
    return sc - s;
}
#endif

static int ee_skip_atoi(const char **s)
{
    int i = 0;
    while (is_digit(**s)) {
        i = i * 10 + *((*s)++) - '0';
    }
    return i;
}

static char ee_number(output_gadget_t *gadget, long num, int base, int size, int precision, int type)
{
    char c;
    char sign, tmp[66];
    char *dig = lower_digits;
    int i;

    if (type & UPPERCASE) dig = upper_digits;
#ifndef TINY_PRINTF
    if (type & LEFT) type &= ~ZEROPAD;
#endif
    if (base < 2 || base > 36) return 0;

    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN) {
        if (num < 0) {
            sign = '-';
            num = -num;
            size--;
        }
#ifndef TINY_PRINTF
        else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
#endif
    }

#ifndef TINY_PRINTF
    if (type & HEX_PREP) {
        if (base == 16)
            size -= 2;
        else if (base == 8)
            size--;
    }
#endif

    i = 0;

    if (num == 0)
        tmp[i++] = '0';
    else {
        while (num != 0) {
            tmp[i++] = dig[((unsigned long)num) % (unsigned)base];
            num = ((unsigned long)num) / (unsigned)base;
        }
    }

    if (i > precision) precision = i;
    size -= precision;
    if (!(type & (ZEROPAD /* TINY option   | LEFT */))) {
        while (size-- > 0) {
            if (putchar_via_gadget(gadget, ' ')) return 1;
        }
    }
    if (sign) {
        if (putchar_via_gadget(gadget, sign)) return 1;
    }

#ifndef TINY_PRINTF
    if (type & HEX_PREP) {
        if (base == 8) {
            if (putchar_via_gadget(gadget, '0')) return 1;
        } else if (base == 16) {
            if (putchar_via_gadget(gadget, '0')) return 1;
            if (putchar_via_gadget(gadget, lower_digits[33])) return 1;
        }
    }
#endif

#ifdef TINY_PRINTF
    while (size-- > 0) {
        if (putchar_via_gadget(gadget, c)) return 1;
    }
#else
    if (!(type & LEFT))
        while (size-- > 0) {
            if (putchar_via_gadget(gadget, c)) return 1;
        }
#endif
    while (i < precision--) {
        if (putchar_via_gadget(gadget, '0')) return 1;
    }
    while (i-- > 0) {
        if (putchar_via_gadget(gadget, tmp[i])) return 1;
    }
    while (size-- > 0) {
        if (putchar_via_gadget(gadget, ' ')) return 1;
    }

    return 0;
}

#ifndef TINY_PRINTF
static char eaddr(output_gadget_t *gadget, unsigned char *addr, int size, int precision, int type)
{
    char tmp[24];
    char *dig = lower_digits;
    int i, len;

    if (type & UPPERCASE) dig = upper_digits;
    len = 0;
    for (i = 0; i < 6; i++) {
        if (i != 0) tmp[len++] = ':';
        tmp[len++] = dig[addr[i] >> 4];
        tmp[len++] = dig[addr[i] & 0x0F];
    }

    if (!(type & LEFT)){
        while (len < size--){
            if (putchar_via_gadget(gadget, ' ')) return 1;
        }
    }
    for (i = 0; i < len; ++i){
        if (putchar_via_gadget(gadget, tmp[i])) return 1;
    }
    while (len < size--){
        if (putchar_via_gadget(gadget, ' ')) return 1;
    }

    return 0;
}

static char iaddr(output_gadget_t *gadget, unsigned char *addr, int size, int precision, int type)
{
    char tmp[24];
    int i, n, len;

    len = 0;
    for (i = 0; i < 4; i++) {
        if (i != 0) tmp[len++] = '.';
        n = addr[i];

        if (n == 0)
            tmp[len++] = lower_digits[0];
        else {
            if (n >= 100) {
                tmp[len++] = lower_digits[n / 100];
                n = n % 100;
                tmp[len++] = lower_digits[n / 10];
                n = n % 10;
            } else if (n >= 10) {
                tmp[len++] = lower_digits[n / 10];
                n = n % 10;
            }

            tmp[len++] = lower_digits[n];
        }
    }

    if (!(type & LEFT)){
        while (len < size--){
            if (putchar_via_gadget(gadget, ' ')) return 1;
        }
    }
    for (i = 0; i < len; ++i){
        if (putchar_via_gadget(gadget, tmp[i])) return 1;
    }
    while (len < size--){
        if (putchar_via_gadget(gadget, ' ')) return 1;
    }

    return 0;
}
#endif

#ifdef HAS_FLOAT
#define CVTBUFSIZE 80
static double modf(double x, double *iptr)
{
	union {double f; size_t i;} u = {x};
	size_t mask;
	int e = (int)(u.i>>52 & 0x7ff) - 0x3ff;

	/* no fractional part */
	if (e >= 52) {
		*iptr = x;
		if (e == 0x400 && u.i<<12 != 0) /* nan */
			return x;
		u.i &= 1ULL<<63;
		return u.f;
	}

	/* no integral part*/
	if (e < 0) {
		u.i &= 1ULL<<63;
		*iptr = u.f;
		return x;
	}

	mask = -1ULL>>12>>e;
	if ((u.i & mask) == 0) {
		*iptr = x;
		u.i &= 1ULL<<63;
		return u.f;
	}
	u.i &= ~mask;
	*iptr = u.f;
	return x - u.f;
}

static char *cvt(double arg, int ndigits, int *decpt, int *sign, char *buf, int eflag)
{
    int r2;
    double fi, fj;
    char *p, *p1;

    if (ndigits < 0) ndigits = 0;
    if (ndigits >= CVTBUFSIZE - 1) ndigits = CVTBUFSIZE - 2;
    r2 = 0;
    *sign = 0;
    p = &buf[0];
    if (arg < 0) {
        *sign = 1;
        arg = -arg;
    }
    arg = modf(arg, &fi);
    p1 = &buf[CVTBUFSIZE];

    if (fi != 0) {
        p1 = &buf[CVTBUFSIZE];
        while (fi != 0) {
            fj = modf(fi / 10, &fi);
            *--p1 = (int)((fj + .03) * 10) + '0';
            r2++;
        }
        while (p1 < &buf[CVTBUFSIZE]) *p++ = *p1++;
    } else if (arg > 0) {
        while ((fj = arg * 10) < 1) {
            arg = fj;
            r2--;
        }
    }
    p1 = &buf[ndigits];
    if (eflag == 0) p1 += r2;
    *decpt = r2;
    if (p1 < &buf[0]) {
        buf[0] = '\0';
        return buf;
    }
    while (p <= p1 && p < &buf[CVTBUFSIZE]) {
        arg *= 10;
        arg = modf(arg, &fj);
        *p++ = (int)fj + '0';
    }
    if (p1 >= &buf[CVTBUFSIZE]) {
        buf[CVTBUFSIZE - 1] = '\0';
        return buf;
    }
    p = p1;
    *p1 += 5;
    while (*p1 > '9') {
        *p1 = '0';
        if (p1 > buf)
            ++*--p1;
        else {
            *p1 = '1';
            (*decpt)++;
            if (eflag == 0) {
                if (p > buf) *p = '0';
                p++;
            }
        }
    }
    *p = '\0';
    return buf;
}

static void ee_bufcpy(char *pd, char *ps, int count)
{
    char *pe = ps + count;
    while (ps != pe)
        *pd++ = *ps++;
}

static void parse_float(double value, char *buffer, char format, int precision)
{
    int decpt, sign, exp, pos;
    char *fdigits = NULL;
    char cvtbuf[CVTBUFSIZE];
    int capexp = 0;
    int magnitude;

    if (format == 'G' || format == 'E') {
        capexp = 1;
        format += 'a' - 'A';
    }

    if (format == 'g') {
        fdigits = cvt(value, precision, &decpt, &sign, cvtbuf, 1);
        magnitude = decpt - 1;
        if (magnitude < -4 || magnitude > precision - 1) {
            format = 'e';
            precision -= 1;
        } else {
            format = 'f';
            precision -= decpt;
        }
    }

    if (format == 'e') {
        fdigits = cvt(value, precision + 1, &decpt, &sign, cvtbuf, 1);

        if (sign) *buffer++ = '-';
        *buffer++ = *fdigits;
        if (precision > 0) *buffer++ = '.';
        ee_bufcpy(buffer, fdigits + 1, precision);
        buffer += precision;
        *buffer++ = capexp ? 'E' : 'e';

        if (decpt == 0) {
            if (value == 0.0)
                exp = 0;
            else
                exp = -1;
        } else
            exp = decpt - 1;

        if (exp < 0) {
            *buffer++ = '-';
            exp = -exp;
        } else
            *buffer++ = '+';

        buffer[2] = (exp % 10) + '0';
        exp = exp / 10;
        buffer[1] = (exp % 10) + '0';
        exp = exp / 10;
        buffer[0] = (exp % 10) + '0';
        buffer += 3;
    } else if (format == 'f') {
        fdigits = cvt(value, precision, &decpt, &sign, cvtbuf, 0);
        if (sign) *buffer++ = '-';
        if (*fdigits) {
            if (decpt <= 0) {
                *buffer++ = '0';
                *buffer++ = '.';
                for (pos = 0; pos < -decpt; pos++) *buffer++ = '0';
                while (*fdigits) *buffer++ = *fdigits++;
            } else {
                pos = 0;
                while (*fdigits) {
                    if (pos++ == decpt) *buffer++ = '.';
                    *buffer++ = *fdigits++;
                }
            }
        } else {
            *buffer++ = '0';
            if (precision > 0) {
                *buffer++ = '.';
                for (pos = 0; pos < precision; pos++) *buffer++ = '0';
            }
        }
    }

    *buffer = '\0';
}

static void decimal_point(char *buffer)
{
    int n;
    while (*buffer) {
        if (*buffer == '.') return;
        if (*buffer == 'e' || *buffer == 'E') break;
        buffer++;
    }

    if (*buffer) {
        n = strnlen(buffer, 256);
        while (n > 0) {
            buffer[n + 1] = buffer[n];
            n--;
        }
        *buffer = '.';
    } else {
        *buffer++ = '.';
        *buffer = '\0';
    }
}

static void cropzeros(char *buffer)
{
    char *stop;
    while (*buffer && *buffer != '.') buffer++;
    if (*buffer++) {
        while (*buffer && *buffer != 'e' && *buffer != 'E') buffer++;
        stop = buffer--;
        while (*buffer == '0') buffer--;
        if (*buffer == '.') buffer--;
        while (buffer != stop)
            *++buffer = 0;
    }
}

static char flt(output_gadget_t *output, double num, int size, int precision, char format, int flags)
{
    char tmp[80];
    char c, sign;
    int n, i;

    // Left align means no zero padding
#ifndef TINY_PRINTF
    if (flags & LEFT) flags &= ~ZEROPAD;
#endif

    // Determine padding and sign char
    c = (flags & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (flags & SIGN) {
        if (num < 0.0) {
            sign = '-';
            num = -num;
            size--;
        }
#ifndef TINY_PRINTF
        else if (flags & PLUS) {
            sign = '+';
            size--;
        } else if (flags & SPACE) {
            sign = ' ';
            size--;
        }
#endif
    }

    // Compute the precision value
    if (precision < 0)
        precision = 6; // Default precision: 6

    // Convert floating point number to text
    parse_float(num, tmp, format, precision);

#ifndef TINY_PRINTF
    if ((flags & HEX_PREP) && precision == 0) decimal_point(tmp);
#endif
    if (format == 'g' && !(flags & HEX_PREP)) cropzeros(tmp);

    n = strnlen(tmp, 256);

    // Output number with alignment and padding
    size -= n;
    if (!(flags & (ZEROPAD | LEFT))){
        while (size-- > 0) {
            if (putchar_via_gadget(output, ' ')) return 1;
        }
    }
    if (sign) {
        if (putchar_via_gadget(output, sign)) return 1;
    }
    if (!(flags & LEFT)){
        while (size-- > 0) {
            if (putchar_via_gadget(output, c)) return 1;
        }
    }
    for (i = 0; i < n; i++) {
        if (putchar_via_gadget(output, tmp[i])) return 1;
    }
    while (size-- > 0){
        if (putchar_via_gadget(output, ' ')) return 1;
    }

    return 0;
}

#endif

#define CHECK_STR_SIZE(_buf, _str, _size) \
    if ((((_str) - (_buf)) >= ((_size)-1))) { break; }

_vsp_inline void format_string_loop(output_gadget_t *output, const char *format, va_list args)
{
    int len;
    unsigned long num;
    int i, base;
    char *s;

    int flags;       // Flags to number()

    int field_width; // Width of output field
    int precision;   // Min. # of digits for integers; max number of chars for from string
    int qualifier;   // 'h', 'l', or 'L' for integer fields

    for (; *format; format++) {
        if (*format != '%') {
            if (putchar_via_gadget(output, *format)) {
                return;
            }
            continue;
        }

        // Process flags
        flags = 0;
#ifdef TINY_PRINTF
        /* Support %0, but not %-, %+, %space and %# */
        format++;
        if (*format == '0') {
            flags |= ZEROPAD;
        }
#else
repeat:
        format++; // This also skips first '%'
        switch (*format) {
        case '-': flags |= LEFT; goto repeat;
        case '+': flags |= PLUS; goto repeat;
        case ' ': flags |= SPACE; goto repeat;
        case '#': flags |= HEX_PREP; goto repeat;
        case '0': flags |= ZEROPAD; goto repeat;
        }
#endif

        // Get field width
        field_width = -1;
        if (is_digit(*format))
            field_width = ee_skip_atoi(&format);
#ifdef TINY_PRINTF
            /* Does not support %* */
#else
        else if (*format == '*') {
            format++;
            field_width = va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }
#endif

        // Get the precision
        precision = -1;
#ifdef TINY_PRINTF
        /* Does not support %. */
#else
        if (*format == '.') {
            ++format;
            if (is_digit(*format))
                precision = ee_skip_atoi(&format);
            else if (*format == '*') {
                ++format;
                precision = va_arg(args, int);
            }
            if (precision < 0) precision = 0;
        }
#endif

        // Get the conversion qualifier
        qualifier = -1;
#ifdef TINY_PRINTF
        /* Does not support %l and %L */
#else
        if (*format == 'l' || *format == 'L') {
            qualifier = *format;
            format++;
        }
#endif

        // Default base
        base = 10;

        switch (*format) {
        case 'c': {
#ifndef TINY_PRINTF
            if (!(flags & LEFT))
#endif
            {
                while (--field_width > 0) {
                    if (putchar_via_gadget(output, ' ')) return;
                }
            }
            // char output
            if (putchar_via_gadget(output, (char)va_arg(args, int))) return;
#ifndef TINY_PRINTF
            // post padding
            while (--field_width > 0) {
                if (putchar_via_gadget(output, ' ')) return;
            }
#endif
            continue;
        }

        case 's': {
            s = va_arg(args, char *);
            if (!s) s = "<NULL>";
#ifdef TINY_PRINTF
            for (len = 0; *s; ++len, ++s)
                ;
#else
            for (len = 0; *s && len < precision; ++len, ++s)
                ;
            if (!(flags & LEFT))
#endif
            {
                while (len < field_width--) {
                    if (putchar_via_gadget(output, ' ')) return;
                }
            }
            for (i = 0; i < len; ++i) {
                if (putchar_via_gadget(output, *s++)) return;
            }
#ifndef TINY_PRINTF
            while (len < field_width--) {
                if (putchar_via_gadget(output, ' ')) return;
            }
#endif
            continue;
        }

#ifdef TINY_PRINTF
        /* Does not support %p, %A, %a, %o */
#else
        case 'p': {
            if (field_width == -1) {
                field_width = 2 * sizeof(void *);
                flags |= ZEROPAD;
            }
            if (ee_number(output, (unsigned long)va_arg(args, void *), 16, field_width, precision, flags)) return;

            continue;
        }

        case 'A': {
            flags |= UPPERCASE;
        }

        case 'a': {
            if (qualifier == 'l') {
                if (eaddr(output, va_arg(args, unsigned char *), field_width, precision, flags)) return;
            } else {
                if (iaddr(output, va_arg(args, unsigned char *), field_width, precision, flags)) return;
            }
            continue;
        }

        // Integer number formats - set up the flags and "break"
        case 'o': {
            base = 8;
            break;
        }
#endif

        case 'X': {
            flags |= UPPERCASE;
        }

        case 'x': {
            base = 16;
            break;
        }

        case 'd':
        case 'i': {
            flags |= SIGN;
        }

        case 'u': {
            break;
        }

#ifdef HAS_FLOAT

        case 'f': {
            if (flt(output, va_arg(args, double), field_width, precision, *format, flags | SIGN)) return;
            continue;
        }

#endif

        default:
            if (*format != '%') {
                if (putchar_via_gadget(output, '%')) return;
            }
            if (*format) {
                if (putchar_via_gadget(output, *format)) return;
            } else{
                --format;
            }
            // CHECK_STR_SIZE(buf, str, size);
            continue;
        }

        if (qualifier == 'l')
            num = va_arg(args, unsigned long);
        else if (flags & SIGN)
            num = va_arg(args, int);
        else
            num = va_arg(args, unsigned int);

        if(ee_number(output, num, base, field_width, precision, flags)) return;
    }
}

// internal vsnprintf - used for implementing _all library functions
static int vsnprintf_impl(output_gadget_t *output, const char *format, va_list args)
{
    size_t null_char_pos;
    // Note: The library only calls vsnprintf_impl() with output->pos being 0. However, it is
    // possible to call this function with a non-zero pos value for some "remedial printing".
    format_string_loop(output, format, args);

    if (!output->function){
        if (output->buffer && output->buff_size != 0) {
            null_char_pos = output->pos < output->buff_size ? output->pos : output->buff_size - 1;
            output->buffer[null_char_pos] = '\0';
        }
    } else {
        putchar_via_gadget(output, '\0');
    }

    // return written chars without terminating \0
    return (int)output->pos;
}

///////////////////////////////////////////////////////////////////////////////

int vsnprintf_(char *s, size_t n, const char *format, va_list arg)
{
    output_gadget_t gadget = GADGET_INITIALIZED;

    if (!s || !n)
        return 0;

    gadget.buffer = s;
    gadget.buff_size = n;

    return vsnprintf_impl(&gadget, format, arg);
}

int vsprintf_(char *s, const char *format, va_list arg)
{
    size_t max_size = 0;
    return vsnprintf_(s, (max_size - 1), format, arg);
}

int vfuncprintf(void (*func)(char c, void *extra_arg), void *extra_arg, const char *format, va_list arg)
{
    output_gadget_t gadget = GADGET_INITIALIZED;

    if (!func)
        return 0;

    gadget.function = func;
    gadget.extra_function_arg = extra_arg;
    return vsnprintf_impl(&gadget, format, arg);
}

int sprintf_(char *s, const char *format, ...)
{
    int ret;
    va_list args;
    va_start(args, format);
    ret = vsprintf_(s, format, args);
    va_end(args);
    return ret;
}

int snprintf_(char *s, size_t n, const char *format, ...)
{
    int ret;
    va_list args;
    va_start(args, format);
    ret = vsnprintf_(s, n, format, args);
    va_end(args);
    return ret;
}

int funcprintf(void (*func)(char c, void *extra_arg), void *extra_arg, const char *format, ...)
{
    int ret;
    va_list args;
    va_start(args, format);
    ret = vfuncprintf(func, extra_arg, format, args);
    va_end(args);
    return ret;
}

#endif
