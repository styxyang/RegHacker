#ifndef _DEBUG_H_
#define _DEBUG_H_

#define MODULE_NAME "RegHacker"
#define DEBUG

#ifdef DEBUG
#define KDBG(fmt, ...) DbgPrint(MODULE_NAME ": " fmt "\n", ##__VA_ARGS__)
#else
#define KDBG(fmt, ...)
#endif

#endif /* _DEBUG_H_ */
