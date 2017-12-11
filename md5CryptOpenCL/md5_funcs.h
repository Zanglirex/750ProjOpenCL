#pragma once
#ifndef _MD5_FUNCS_H
#define _MD5_FUNCS_H

#include <ctype.h>
#include "types.h"

u8 int_to_itoa64(const u8 c);
u8 itoa64_to_int(const u8 c);

static void md5crypt_decode(u8 digest[16], u8 buf[22]);
static void md5crypt_encode(const u8 digest[16], u8 buf[22]);
int md5crypt_parse_hash(u8 *input_buf, u32 input_len, hash_t *hash_buf);

#endif