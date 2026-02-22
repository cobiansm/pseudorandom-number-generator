/*
 *  Tarea 05 - Cifrado Chacha20
 *  Marlene Cobian
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"

#define ROTL32( value, amount ) \
    ( (uint32_t) ( (value) << (amount) ) | ( (value) >> ( 32 - (amount) ) ) )

static inline void chacha20_quarter_round( uint32_t state[16],
                                           size_t a,
                                           size_t b,
                                           size_t c,
                                           size_t d );
void generate_keystream_64bytes(uint32_t original_state[16], uint8_t keystream[64]);
void chacha20_encrypt(uint32_t *state, uint8_t *mensaje, uint8_t *salida, size_t len);


static inline void chacha20_quarter_round( uint32_t state[16],
                                           size_t a,
                                           size_t b,
                                           size_t c,
                                           size_t d )
{
    /* a += b; d ^= a; d <<<= 16; */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 16 );

    /* c += d; b ^= c; b <<<= 12 */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 12 );

    /* a += b; d ^= a; d <<<= 8; */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32( state[d], 8 );

    /* c += d; b ^= c; b <<<= 7; */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32( state[b], 7 );
}

void generate_keystream_64bytes(uint32_t original_state[16], uint8_t keystream[64]) {
    uint32_t x[16];

    /* Copy the state */
    memcpy(x, original_state, sizeof(uint32_t) * 16);

    /* 20 rounds */
    for (int i = 0; i < 10; i++) {
        // Columns
        chacha20_quarter_round(x, 0, 4, 8, 12);
        chacha20_quarter_round(x, 1, 5, 9, 13);
        chacha20_quarter_round(x, 2, 6, 10, 14);
        chacha20_quarter_round(x, 3, 7, 11, 15);
        // Diagonals
        chacha20_quarter_round(x, 0, 5, 10, 15);
        chacha20_quarter_round(x, 1, 6, 11, 12);
        chacha20_quarter_round(x, 2, 7, 8, 13);
        chacha20_quarter_round(x, 3, 4, 9, 14);
    }

    /* Final sum */
    for (int i = 0; i < 16; i++) {
        x[i] += original_state[i];
    }

    /* Conversion 32 bits to bytes */
    for (int i = 0; i < 16; i++) {
        keystream[i * 4 + 0] = (uint8_t)(x[i] >> 0);
        keystream[i * 4 + 1] = (uint8_t)(x[i] >> 8);
        keystream[i * 4 + 2] = (uint8_t)(x[i] >> 16);
        keystream[i * 4 + 3] = (uint8_t)(x[i] >> 24);
    }
}

void chacha20_encrypt(uint32_t *state, uint8_t *mensaje, uint8_t *salida, size_t len) {
    uint8_t keystream[64];

    generate_keystream_64bytes(state, keystream);

    /* Cipher (XOR) */
    for (size_t i = 0; i < len; i++) {
        salida[i] = mensaje[i] ^ keystream[i];
    }

    /* Increment counter */
    state[12]++;
}

int main(void) {

	/* HW init */
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

	uint32_t state[16];

	/* expand 32-byte k */
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;

	/* Simple key */
	for(int i=4; i<12; i++) state[i] = 0x01020304;

	/* Initial counter */
	state[12] = 0;

	/* Nonce */
	state[13] = 0x00000000;
	state[14] = 0x00000000;
	state[15] = 0x00000001;

	/* Message to encrypt */
	uint8_t plain_text[] = "Mensaje secreto para cifrar con chacha 20";
	size_t len = strlen((char *)plain_text);
	uint8_t encrypted_text[64] = {0};
	uint8_t decrypted_text[64] = {0};

	/* Encrypt */
	PRINTF("Texto Original: %s\r\n", plain_text);

	chacha20_encrypt(state, plain_text, encrypted_text, len);

	PRINTF("Texto Cifrado (HEX): ");
	for(size_t i = 0; i < len; i++) {
		PRINTF("%02X ", encrypted_text[i]);
	}
	PRINTF("\r\n");

	/* Decrypt */
	state[12] = 0;
	chacha20_encrypt(state, encrypted_text, decrypted_text, len);

	decrypted_text[len] = '\0';
	PRINTF("Texto Descifrado: %s\r\n", decrypted_text);

	while (1) {
	}
}
