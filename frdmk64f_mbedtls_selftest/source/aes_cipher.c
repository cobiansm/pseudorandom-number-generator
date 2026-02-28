/*
 *  Tarea 07 - Cifrado AES
 *  Marlene Cobian
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "mbedtls/aes.h"

int main(void) {

	/* HW init */
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

	PRINTF("--- AES-128-CBC with mbedTLS ---\r\n\n");

	/* AES 16 byte key */
	unsigned char key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	/* initializing vector */
	unsigned char iv[16] = "init_vector_aes_";
	unsigned char iv_copy[16];
	memcpy(iv_copy, iv, 16);

	/* Message to encrypt */
	unsigned char plain_text[32] = "Mensaje encriptado con AES-128";
	unsigned char encrypted_message[32];
	unsigned char decrypted_message[32];

	/* mbedTLS context */
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	/* Encrypt */
	mbedtls_aes_setkey_enc(&aes, key, 128);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv_copy, plain_text, encrypted_message);

	PRINTF("Encrypted message:\r\n");
	for(int i=0; i<16; i++) {
		PRINTF("%02x ", encrypted_message[i]);
	}
	PRINTF("\r\n\n");

	/* Decrypt */
	memcpy(iv_copy, iv, 16);
	mbedtls_aes_setkey_dec(&aes, key, 128);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv_copy, encrypted_message, decrypted_message);

	decrypted_message[31] = '\0';
	PRINTF("Decrypted message:\r\n%s\r\n", decrypted_message);

	/* Free */
	mbedtls_aes_free(&aes);

	while (1) {
	}
}
