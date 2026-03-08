/*
 *  Tarea 06 - Función hash SHA-256
 *  Marlene Cobian
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "mbedtls/sha256.h"

int main(void) {

	/* HW init */
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

	PRINTF("--- SHA-256 with mbedTLS ---\r\n\n");

	/* Message to process */
	unsigned char plain_text[] = "Mensaje procesado con SHA-256";
	unsigned char output_hash[32];

	/* mbedTLS context */
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);

	/* Process and give plain text */
	mbedtls_sha256_starts_ret(&ctx, 0);
	mbedtls_sha256_update_ret(&ctx, plain_text, strlen((char *)plain_text));

	/* Output hash */
	mbedtls_sha256_finish_ret(&ctx, output_hash);

	/* Show hash */
	PRINTF("Plain text: %s\r\n", plain_text);
	PRINTF("SHA-256 Hash:\r\n");
	for(int i=0; i < 32; i++) {
		PRINTF("%02x", output_hash[i]);
	}
	PRINTF("\r\n\n");

	/* Free */
	mbedtls_sha256_free(&ctx);

	while (1) {
	}
}
