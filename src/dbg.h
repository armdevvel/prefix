#ifndef _PREFIX_SRC_DBG_H_
#define _PREFIX_SRC_DBG_H_

#ifdef _PREFIX_DEBUG
#include <stdio.h>

#define _PREFIX_LOG(format, ...) { fprintf(_PREFIX_DEBUG, format "\n", ##__VA_ARGS__); fflush(_PREFIX_DEBUG); }
#else
#define _PREFIX_LOG(...)
#endif

#endif /* _PREFIX_SRC_DBG_H_ */
