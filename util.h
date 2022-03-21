#ifndef _util_h_
#define _util_h_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

FILE *output;

// Big-Little Endian Conversion
extern u_int16_t BSWAP_16(u_int16_t x);
extern u_int32_t BSWAP_32(u_int32_t x);

#endif