/*
 * Simple test for OpenSSL CMAC (RFC 4493) API using test vectors from
 * http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
 * (corrected version of Appendix D of Special Publication 800-38B, which
 * specifies examples for the CMAC authentication mode)
 *
 * Usage: cmactest [engine_name]
 *
 * Run and check for program exit code: if 0 it succeeded, otherwise failed.
 *
 * It is recommended to run this with native implementation and OpenSSL
 * PKCS#11 engine, i.e.:
 *
 *   ./a.out
 *   echo $?
 *   ./a.out pkcs11
 *   echo $?
 *
 * Written by Vladimir Kotal, 2015 for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *
 * Portions of the attached software ("Contribution") are developed by
 * Oracle, Inc., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 */

#include <stdio.h>
#include <strings.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/cmac.h>

typedef struct cmac_test {
	char *name;
	char *key;
	size_t key_len;
	char *message;
	size_t message_len;
	char *mac;
	size_t mac_len;
} cmac_test_t;

cmac_test_t test_vects[] = {
    /* Example 1: Mlen = 0 */
    {
      "AES-128 M=0",
      "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
      "", 0,
      "\xbb\x1d\x69\x29\xe9\x59\x37\x28\x7f\xa3\x7d\x12\x9b\x75\x67\x46", 16
    },
    /* Example 2: Mlen = 128 */
    {
      "AES-128 M=128",
      "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16,
      "\x07\x0a\x16\xb4\x6b\x4d\x41\x44\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c", 16
    },
    /* Example 3: Mlen = 320 */
    {
      "AES-128 M=320",
      "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
      40,
      "\xdf\xa6\x67\x47\xde\x9a\xe6\x30\x30\xca\x32\x61\x14\x97\xc8\x27", 16
    },
    /* Example 4: Mlen = 512 */
    {
      "AES-128 M=512",
      "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
      "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 64,
      "\x51\xf0\xbe\xbf\x7e\x3b\x9d\x92\xfc\x49\x74\x17\x79\x36\x3c\xfe", 16
    },
    /* Example 5: Mlen = 0 */
    {
      "AES-192 M=0",
      "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
      "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
      "", 0,
      "\xd1\x7d\xdf\x46\xad\xaa\xcd\xe5\x31\xca\xc4\x83\xde\x7a\x93\x67", 16
    },
    /* Example 6: Mlen = 128 */
    {
      "AES-192 M=128",
      "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
      "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16,
      "\x9e\x99\xa7\xbf\x31\xe7\x10\x90\x06\x62\xf6\x5e\x61\x7c\x51\x84", 16
    },
    /* Example 7: Mlen = 320 */
    {
      "AES-192 M=320",
      "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
      "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11", 40,
      "\x8a\x1d\xe5\xbe\x2e\xb3\x1a\xad\x08\x9a\x82\xe6\xee\x90\x8b\x0e", 16
    },
    /* Example 8: Mlen = 512 */
    {
      "AES-192 M=512",
      "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
      "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
      "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 64,
      "\xa1\xd5\xdf\x0e\xed\x79\x0f\x79\x4d\x77\x58\x96\x59\xf3\x9a\x11", 16
    },
    /* Example 9: Mlen = 0 */
    {
      "AES-256 M=0",
      "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
      "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
      "", 0,
      "\x02\x89\x62\xf6\x1b\x7b\xf8\x9e\xfc\x6b\x55\x1f\x46\x67\xd9\x83", 16
    },
    /* Example 10: Mlen = 128 */
    {
      "AES-256 M=128",
      "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
      "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16,
      "\x28\xa7\x02\x3f\x45\x2e\x8f\x82\xbd\x4b\xf2\x8d\x8c\x37\xc3\x5c", 16
    },
    /* Example 11: Mlen = 320 */
    {
      "AES-256 M=320",
      "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
      "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11", 40,
      "\xaa\xf3\xd8\xf1\xde\x56\x40\xc2\x32\xf5\xb1\x69\xb9\xc9\x11\xe6", 16
    },
    /* Example 12: Mlen = 512 */
    {
      "AES-256 M=512",
      "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
      "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
      "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
      "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
      "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
      "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 64,
      "\xe1\x99\x21\x90\x54\x9f\x6e\xd5\x69\x6a\x2c\x05\x6c\x31\x54\x10", 16
    },
};

int failed;

static void
print_array(char *array, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		printf("%02x ", (unsigned char)array[i]);
	printf("\n");
}

static const EVP_CIPHER*
get_cipher(char *name)
{
	if (strncmp(name, "AES-128", 7) == 0)
		return (EVP_aes_128_cbc());
	if (strncmp(name, "AES-192", 7) == 0)
		return (EVP_aes_192_cbc());
	if (strncmp(name, "AES-256", 7) == 0)
		return (EVP_aes_256_cbc());
	else {
		fprintf(stderr, "unknown cipher: %s", name);
		exit(1);
	}
}

static void
test(cmac_test_t *t)
{
	char mact[16] = { 0 };
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "NULL ctx");
		exit(1);
	}

	if (CMAC_Init(ctx, t->key, t->key_len, get_cipher(t->name), NULL) == 0) {
		fprintf(stderr, "CMAC_Init() failed");
		exit(1);
	}
	if (CMAC_Update(ctx, t->message, t->message_len) == 0) {
		fprintf(stderr, "CMAC_Update() failed");
		exit(1);
	}
	if (CMAC_Final(ctx, (unsigned char *)mact, &mactlen) == 0) {
		fprintf(stderr, "CMAC_Final() failed");
		exit(1);
	}
	CMAC_CTX_free(ctx);

	printf("%16s: ", t->name);
	if (bcmp(t->mac, mact, sizeof (mact)) != 0) {
		printf("FAIL\n");
		printf("\tnot identical MACs\n");
		printf("\texpected: ");
		print_array(t->mac, t->mac_len);
		printf("\tactual:   ");
		print_array(mact, sizeof (mact));
		failed = 1;
	} else {
		printf("PASS\n");
	}
}

void
setup_engine(const char *engine)
	{
        ENGINE *e = NULL;

        ENGINE_load_builtin_engines();
	ENGINE_register_all_ciphers();

        printf("looking for engine '%s'\n", engine);
        if ((e = ENGINE_by_id(engine)) == NULL)
		{
                fprintf(stderr, "ERROR - invalid engine \"%s\"\n", engine);
                exit(1);
		}

	if (!ENGINE_init(e)) {
		ENGINE_free(e);
		fprintf(stderr, "ERROR - ENGINE_init for %s failed\n", engine);
		exit(1);
	}

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
		{
                fprintf(stderr, "ERROR - can't use that engine\n");
                exit(1);
		}

        printf("engine '%s' set\n", ENGINE_get_id(e));
}

int
main(int argc, char *argv[])
{
	size_t i;

	/* Load up the software EVP_CIPHER definitions. */
	OpenSSL_add_all_ciphers();

	if (argc == 2)
		setup_engine(argv[1]);

	printf("testing CMAC vectors\n");
	for (i = 0; i < sizeof (test_vects) / sizeof (test_vects[0]); i++)
		test(&test_vects[i]);

	return (failed);
}
