
#ifndef INTERPRETER_H
#define INTERPRETER_H

#include <stdint.h>

#define DEV_MODE        0

#define BIT1            1
#define BIT2            1 << 1
#define BIT3            1 << 2
#define BIT4            1 << 3
#define BIT5            1 << 4

#define CIRC_SHIFT_CHAR_LEFT(shiftc, ch) ((((ch) >> (8 - (shiftc))) | ((ch) << (shiftc))) & 0xff)
#define CIRC_SHIFT_CHAR_RIGHT(shiftc, ch) (CIRC_SHIFT_CHAR_LEFT(8 - shiftc, ch))

#define MAKE_CODE(shiftc, letter, bit_count, morse_repr)                    \
    (uint32_t)                                                              \
        (((shiftc) << 24)                                                   \
        | (CIRC_SHIFT_CHAR_RIGHT(shiftc, letter) << 16)                     \
        | ((bit_count) << 8)                                                \
        | (morse_repr))


#endif // INTERPRETER_H
