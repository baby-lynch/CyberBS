#ifndef _util_h_
#define _util_h_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *output;

// Big-Little Endian Conversion
extern u_int16_t BSWAP_16(u_int16_t x);
extern u_int32_t BSWAP_32(u_int32_t x);

// Low-High 4 bit manipulation of ONE BYTE
extern u_int8_t Low_4(u_int8_t x);
extern u_int8_t High_4(u_int8_t x);

#endif