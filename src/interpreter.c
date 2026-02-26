
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <math.h>

#include "./include/interpreter.h"

/**
 * What is this CTF?
 * 
 * For a while I have wanted to make something that uses morse in some manner, hence this CTF.
 * The overall idea was to create something that would store the flag in an obfuscated some morse
 * representation, and then validating the users provided flag converting it to morse and then 
 * deobfuscating the flag at runtime before comparing the two morse codes. Since morse is kinda
 * weird with the number of characters required to represent each letter may differ in length,
 * an example being that 'e' is simply '.' but 'y' is '-.--', as such some form of mapping is 
 * required to convert letter -> morse. However, making this mapping using plain text for the
 * morse and letters would be obvious asf, so I encoded each mapping into a 32 bit int!
 * 
 * So, each 32 bit int encodes a mapping from english character -> morse character as follows
 *  - [0-8)   encodes the morse representation of the character itself. A 0 denotes a dot, and 1 a dash.
 *  - [8-16)  denotes the number of morse symbols (dots & dashes) needed a character (since they vary between 1 and 5 symbols)
 *  - [16-24) encodes the english letter, in memory it is shifted right for more obfuscation :) , details below
 *  - [24-32) specifies how many times the letter stored in [16-24) is shifted in memory so it can't be seen conveniently
 *               in ghidra or any hex viewer
 *
 * Example for character 'f' (with a shift count of 2):
 *  - The morse symbol for 'f' is ..-.
 *  - The [0-8) encodes the morse symbol as follows:
 *     1 << 1 = [0000]0010
 *  - Since there are 4 characters in the morse symbol, [8-16) encoded as:
 *     4 = 00000100
 *  - Lastly, the upper 16 encodes 'f' and how many times it gets shifted. If it gets shifted twice then:
 *     [24-32) = 00000010
 *     [16-24) = 01100110 => 00110011 => 10011001
 * 
 * The flag is:
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

static uint8_t compare_morse(uint32_t c1, uint32_t c2);

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
    3639668985,
    1819834493,
    909917247,
    454958622,
    2374962958,
    3334965126,
    3814966210,
    4054966752,
    4174967025,
    2087483513,
    1043741757,
    521870879,
    260935438,
    2277951366,
    3286459330,
    3790713312,
    4042840305,
    2021420153,
    0
};


int
main(int argc, char **argv) {
    printf("\nPlease enter a flag below!\n > ");

    char *user_input = NULL;
    size_t len = 0;
    ssize_t read = 0;
    if ((read = getline(&user_input, &len, stdin)) == -1) {
        printf("Failed to read user input. Exiting...\n");
        exit(1);
    }
    user_input[read - 1] = '\0';
    
    if (check_flag(user_input)) {
        printf("Well done! You found the flag :) Please submit the following:\n");
        printf("%s\n\n", user_input);
    } else {
        printf("Incorrect flag, please try again!\n");
    }
    return 0;
}


/**
 * iterate each character, retrieve the uint32 that has the char embedded within it
 * before decoding the morse portion and verifying it against the key.  
 */
static bool
check_flag(char *input) {
    uint32_t *flag = _flag;
    while (*input && *flag) {
        uint32_t code = retrieve_code_by_letter(*input);
        uint32_t flag_at = *flag;

        shift_key();
        if (compare_morse(flag_at ^ _key, code))
            return false;
        
        input++;
        flag++;
    }
    if (*input != 0 || *flag != 0)
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


// functions to extract data from uint32_t

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

static uint8_t
compare_morse(uint32_t c1, uint32_t c2) {
    char c1_morse[6] = { '\0' };
    char c2_morse[6] = { '\0' };

    extract_morse_as_str(c1, c1_morse);
    extract_morse_as_str(c2, c2_morse);

    return strlen(c1_morse) == strlen(c2_morse) 
            && strcmp(c1_morse, c2_morse) == 0;
}

static void
extract_morse_as_str(uint32_t code, char *buf) {
    int8_t num_bits = (int8_t)bits_in_encoded_morse(code);
    uint8_t morse = encoded_morse(code);
    for (int8_t i = num_bits - 1, j = 0; i >= 0; i--, j++) {
        if ((morse & (1 << i)) != 0)
            buf[j] = 45;    // '-'
        else
            buf[j] = 46;   // '.'
    }
}




#if DEV_MODE

static void
generate_flag() {
    const char *flag = "the0world0says0hii";
    char ch;
    for (int i = 0; i < 18; ch = flag[i], i++) {
        shift_key();

        uint32_t code = retrieve_code_by_letter(ch);
        uint16_t morse_information = code && 0xffff;
        uint32_t flag_value = morse_information ^ _key;

        printf("%u,\n", flag_value);
    }
}

static void
output_morse(const char c) {
    uint32_t code = retrieve_code_by_letter(c);
    if (code == UINT32_MAX) {
        printf("Unrecognised character '%c'!\nExiting...\n", c);
        return;
    }

    uint8_t num_bits = bits_in_encoded_morse(code);
    uint8_t morse = encoded_morse(code);
    printf("%c ==> ", c);
    for (int i = num_bits - 1; i >= 0; i--) {
        if ((morse & (1 << i)) != 0) {
            printf("%c", '-');
        } else {
            printf("%c", '.');
        }
    }
    printf(",\n");
}

#endif