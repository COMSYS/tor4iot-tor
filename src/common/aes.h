/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Implements a minimal interface to counter-mode AES. */

#ifndef TOR_AES_H
#define TOR_AES_H

/**
 * \file aes.h
 * \brief Headers for aes.c
 */

typedef struct aes_cnt_cipher aes_cnt_cipher_t;

aes_cnt_cipher_t* aes_new_cipher(const uint8_t *key, const uint8_t *iv,
                                 int key_bits);
void aes_cipher_free(aes_cnt_cipher_t *cipher);
void aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len);

//Tor4IoT: Copy AES cipher struct
aes_cnt_cipher_t* aes_cipher_copy(aes_cnt_cipher_t *in);

int evaluate_evp_for_aes(int force_value);
int evaluate_ctr_for_aes(void);

#endif /* !defined(TOR_AES_H) */

