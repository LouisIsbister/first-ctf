
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include "./include/checker.h"

/**
 * What is this CTF?
 * 
 * For a while I have wanted to make something that uses morse in some manner, si thats the gist of this CTF.
 * The overall idea was to create something that would store the flag in some obfuscated morse
 * representation, and then validate the users provided flag by converting it to morse, 
 * deobfuscating the flag at runtime, and comparing the two morse codes. Since morse is kinda
 * weird, the number of characters required to represent each letter differs heaps,
 * for example, 'e' is simply '.' but 'y' is '-.--', as such, some form of mapping is 
 * required to convert letter -> morse. However, making this mapping using plain text for the
 * morse and letters would be obvious asf, so I encoded each mapping into a 32 bit int to obfuscate
 * it a bit;
 * 
 * So, each 32 bit int encodes a mapping from english character -> morse character as follows
 *  - [0-8)   encodes the morse representation of the character itself. A 0 denotes a dot, and 1 a dash.
 *  - [8-16)  denotes the number of symbols (dots and dashes) needed by a character
 *  - [16-24) encodes the english letter, in memory it is shifted right for more obfuscation :) , details below
 *  - [24-32) specifies how many times the letter stored in [16-24) is shifted in memory so it can't be seen conveniently
 *               in ghidra or any other sophisticated decompiler / hex viewer
 *
 * The flag for testing:
 * the0world0says0hii
 */ 

static bool check_flag(char *input);
static uint32_t retrieve_code_by_letter(const char c);
static char retrieve_decoded_letter(uint32_t code);
static void shift_key();

static uint8_t letter_shift_count(uint32_t code);     // extract [24, 32)
static uint8_t shifted_letter(uint32_t code);         // extract [16, 24)
static uint8_t bits_in_encoded_morse(uint32_t code);  // extract [8, 16)
static uint8_t encoded_morse(uint32_t code);          // extract [0, 8)

static bool compare_morse_codes(uint32_t c1, uint32_t c2);

#if DEV_MODE
static void generate_flag();
static void output_morse(const char c);
#endif


static uint32_t _codes[] = 
{
    MAKE_CODE(1, 'a', 2, BIT1),                                // .-
    MAKE_CODE(3, 'b', 4, BIT4),                                // -...
    MAKE_CODE(4, 'c', 4, BIT4 | BIT2),                         // -.-.
    MAKE_CODE(6, 'd', 3, BIT3),                                // -..
    MAKE_CODE(2, 'e', 1, 0),                                   // .
    MAKE_CODE(5, 'f', 4, BIT2),                                // ..-.
    MAKE_CODE(7, 'g', 3, BIT3 | BIT2),                         // --.
    MAKE_CODE(1, 'h', 4, 0),                                   // ....
    MAKE_CODE(4, 'i', 2, 0),                                   // ..
    MAKE_CODE(5, 'j', 4, BIT3 | BIT2 | BIT1),                  // .---
    MAKE_CODE(3, 'k', 3, BIT3 | BIT1),                         // -.-
    MAKE_CODE(3, 'l', 4, BIT3),                                // .-..
    MAKE_CODE(6, 'm', 2, BIT2 | BIT1),                         // --
    MAKE_CODE(4, 'n', 2, BIT2),                                // -.
    MAKE_CODE(3, 'o', 3, BIT3 | BIT2 | BIT1),                  // ---
    MAKE_CODE(2, 'p', 4, BIT3 | BIT2),                         // .--.
    MAKE_CODE(3, 'q', 4, BIT4 | BIT3 | BIT1),                  // --.-
    MAKE_CODE(7, 'r', 3, BIT2),                                // .-.
    MAKE_CODE(7, 's', 3, 0),                                   // ...
    MAKE_CODE(4, 't', 1, BIT1),                                // -
    MAKE_CODE(7, 'u', 3, BIT1),                                // ..-
    MAKE_CODE(2, 'v', 4, BIT1),                                // ...-
    MAKE_CODE(5, 'w', 3, BIT2 | BIT1),                         // .--
    MAKE_CODE(3, 'x', 4, BIT4 | BIT1),                         // -..-
    MAKE_CODE(6, 'y', 4, BIT4 | BIT2 | BIT1),                  // -.--
    MAKE_CODE(2, 'z', 4, BIT4 | BIT3),                         // --..
    MAKE_CODE(1, '0', 5, BIT5 | BIT4 | BIT3 | BIT2 | BIT1),    // -----
    MAKE_CODE(1, '1', 5, BIT4 | BIT3 | BIT2 | BIT1),           // .----
    MAKE_CODE(2, '2', 5, BIT3 | BIT2 | BIT1),                  // ..---
    MAKE_CODE(1, '3', 5, BIT2 | BIT1),                         // ...--
    MAKE_CODE(4, '4', 5, BIT1),                                // ....-
    MAKE_CODE(5, '5', 5, 0),                                   // .....
    MAKE_CODE(2, '6', 5, BIT5),                                // -....
    MAKE_CODE(7, '7', 5, BIT5 | BIT4),                         // --...
    MAKE_CODE(3, '8', 5, BIT5 | BIT4 | BIT3),                  // ---..
    MAKE_CODE(1, '9', 5, BIT5 | BIT4 | BIT3 | BIT2),           // ----.
};

static uint32_t _key = 0xb1e1e1f1;

static uint32_t _flag[] =
{
    3703042553,
    1833729148,
    879050046,
    436607744,
    2285112332,
    3307897984,
    3834101953,
    4064077285,
    4266259444,
    2104786279,
    969948988,
    514530335,
    157846276,
    2149631111,
    3271255772,
    3771053537,
    4100905712,
    2095738488,
    0
};


static void
read_user_flag(char **input_buf) {
    size_t len = 0;
    ssize_t read = 0;
    if ((read = getline(input_buf, &len, stdin)) == -1) {
        printf("Failed to read user input. Exiting...\n");
        exit(1);
    }
    *((*input_buf) + read - 1) = '\0';
}


int
main(int argc, char **argv) {
    // generate_flag();
    printf("\nPlease enter a flag below!\n > ");

    char *input_buf = NULL;
    read_user_flag(&input_buf);

    // printf("'%s'", input_buf);

    if (check_flag(input_buf)) {
        printf("Well done! You found the flag :) Please submit the following:\n");
        printf("%s\n\n", input_buf);
    } else {
        printf("Incorrect flag, please try again!\n");
    }
    return 0;
}



/**
 * iterate each character, retrieve the uint32 that has the extpected char embedded within it
 * before decoding the morse portion and verifying it against the key.  
 */
static bool
check_flag(char *input) {
    uint32_t *flag = _flag;
    time_t start_t;
    while (*input && *flag) {
        start_t = time(NULL);
        
        shift_key();
        VERIFY_TIME(start_t);

        uint32_t recved_code = retrieve_code_by_letter(*input);
        VERIFY_TIME(start_t);

        uint32_t exped_code = *flag ^ _key;
        if (!compare_morse_codes(exped_code, recved_code))
            return false;

        VERIFY_TIME(start_t);
        
        input++;
        flag++;
    }
    if (*input != '\0' || *flag != '\0')
        return false;

    return true;
}

static uint32_t
retrieve_code_by_letter(const char letter) {
    uint32_t *ptr = _codes;
    while (*ptr != 0) {
        uint32_t code = *ptr;
        char decoded = retrieve_decoded_letter(code);
        if (decoded == letter)
            return code;
        ptr++;
    }
    printf("Unrecognised character '%c'!\nExiting...\n", letter);
    exit(1);
}

static char
retrieve_decoded_letter(uint32_t code) {
    uint8_t shiftc = letter_shift_count(code);
    uint8_t shifted = shifted_letter(code);
    return CIRC_SHIFT_CHAR_LEFT(shiftc, shifted);
}

static void
shift_key() {
    _key = (_key << ((sizeof(_key) * 8) - 1)) | (_key >> 1);
}


// functions to extract data from encoded 32 bit int

static uint8_t
letter_shift_count(uint32_t code) {
    return (uint8_t) ((code >> 24) & 0xff);
}

static uint8_t
shifted_letter(uint32_t code) {
    return (uint8_t) ((code >> 16) & 0xff);
}

static uint8_t
bits_in_encoded_morse(uint32_t code) {
    return (uint8_t) ((code >> 8) & 0xff);
}

static uint8_t
encoded_morse(uint32_t code) {
    return (uint8_t) (code & 0xff);
}


// morse code string comparision

static void extract_morse_as_str(uint32_t code, char *buf);

static bool
compare_morse_codes(uint32_t c1, uint32_t c2) {
    char c1_buf[6] = { '\0' };
    char c2_buf[6] = { '\0' };

    extract_morse_as_str(c1, c1_buf);
    extract_morse_as_str(c2, c2_buf);

    return strlen(c1_buf) == strlen(c2_buf) 
            && strcmp(c1_buf, c2_buf) == 0;
}

static void
extract_morse_as_str(uint32_t code, char *buf) {
    time_t start_t = time(NULL);

    int8_t num_bits = (int8_t)bits_in_encoded_morse(code);
    uint8_t morse = encoded_morse(code);
    for (int8_t i = num_bits - 1, j = 0; i >= 0; i--, j++) {
        if ((morse & (1 << i)) != 0)
            buf[j] = 45;    // '-'
        else
            buf[j] = 46;    // '.'
        VERIFY_TIME(start_t);
    }
}




#if DEV_MODE

static void
generate_flag() {
    char *flag = "the0world0says0hii";
    for (int i = 0; i < 18; i++, flag++) {
        shift_key();

        uint32_t code = retrieve_code_by_letter(*flag);
        uint32_t flag_value = code ^ _key;

        printf("%u,\n", flag_value);
    }
}

static void
output_morse(const char c) {
    uint32_t code = retrieve_code_by_letter(c);
    if (code == UINT32_MAX) {
        printf("Unrecognised character '%c'!\n", c);
        return;
    }

    uint8_t num_bits = bits_in_encoded_morse(code);
    uint8_t morse = encoded_morse(code);
    printf("%c ==> ", c);
    for (int i = num_bits - 1; i >= 0; i--) {
        if ((morse & (1 << i)) != 0)
            printf("%c", '-');
        else
            printf("%c", '.');
    }
    printf(",\n");
}

#endif