#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H
 /* Source : CS240 lab1 source code. Author : Sergio Benitez, TA */


/*
 * The macros below are for debugging and printing out verbose output. They are
 * similar to the Linux debug macros in that defining DEBUG will enable debug
 * output. The verbose macro will print if DEBUG was defined or if the `active`
 * parameter is true.
 */
#ifdef DEBUG
    #define DEBUG_ 1
#else
    #define DEBUG_ 0
#endif

#define debug_cond(condition, stream, ...) \
    do { \
        if ((condition)) { \
            fprintf(stream, "%s:%d:%s(): ", __FILE__, __LINE__, __func__); \
            fprintf(stream, __VA_ARGS__); \
        } \
    } while (0)

#define debug(...) debug_cond(DEBUG_, stderr, __VA_ARGS__)

#define verbose(active, ...) debug_cond(DEBUG_ || active, stderr, __VA_ARGS__);

#define if_debug \
  if (DEBUG_)

/*
 * The macros below are helper macros for printing error messages.
 * Additionally, err_exit will exit with a failing return code after printing
 * the message.
 */
#define print_err(...) \
    do { \
        fprintf(stderr, "ERROR: "); \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr); \
    } while (0)

#define err_exit(...) \
    do { \
        print_err(__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)




#endif 