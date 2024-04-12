#ifndef PRINTF_CONFIG_H_
#define PRINTF_CONFIG_H_


// 'ntoa' conversion buffer size, this must be big enough to hold one converted
// numeric number including padded zeros (dynamically created on stack)
#define PRINTF_INTEGER_BUFFER_SIZE                  32

// size of the fixed (on-stack) buffer for printing individual decimal numbers.
// this must be big enough to hold one converted floating-point value including
// padded zeros.
#define PRINTF_DECIMAL_BUFFER_SIZE                  32

// Support for the decimal notation floating point conversion specifiers (%f, %F)
#define PRINTF_SUPPORT_DECIMAL_SPECIFIERS           1

// Support for the exponential notation floating point conversion specifiers (%e, %g, %E, %G)
#define PRINTF_SUPPORT_EXPONENTIAL_SPECIFIERS       0

// Support for the length write-back specifier (%n)
#define PRINTF_SUPPORT_WRITEBACK_SPECIFIER          0

// Default precision for the floating point conversion specifiers (the C standard sets this at 6)
#define PRINTF_DEFAULT_FLOAT_PRECISION              6

// Default choice of type to use for internal floating-point computations
#define PRINTF_USE_DOUBLE_INTERNALLY                0

// According to the C languages standard, printf() and related functions must be able to print any
// integral number in floating-point notation, regardless of length, when using the %f specifier -
// possibly hundreds of characters, potentially overflowing your buffers. In this implementation,
// all values beyond this threshold are switched to exponential notation.
#define PRINTF_MAX_INTEGRAL_DIGITS_FOR_DECIMAL      9

// Support for the long long integral types (with the ll, z and t length modifiers for specifiers
// %d,%i,%o,%x,%X,%u, and with the %p specifier). Note: 'L' (long double) is not supported.
#define PRINTF_SUPPORT_LONG_LONG                    0

// The number of terms in a Taylor series expansion of log_10(x) to
// use for approximation - including the power-zero term (i.e. the
// value at the point of expansion).
#define PRINTF_LOG10_TAYLOR_TERMS                   4

// Be extra-safe, and don't assume format specifiers are completed correctly
// before the format string end.
#define PRINTF_CHECK_FOR_NUL_IN_FORMAT_SPECIFIER    0

#define PRINTF_ALIAS_STANDARD_FUNCTION_NAMES_HARD   1

#endif /* PRINTF_CONFIG_H_ */
