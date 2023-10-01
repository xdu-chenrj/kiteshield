#ifndef __KITESHIELD_TYPES_H
#define __KITESHIELD_TYPES_H

/* Gets us NULL and size_t
 * (use of a system header is ok here as this a a freestanding header) */
#include <stddef.h>
#ifndef _STDIO_H
typedef long int ssize_t;
typedef long int off_t;
typedef int pid_t;
#endif

#endif /* __KITESHIELD_TYPES_H */

