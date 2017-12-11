#pragma once
/**
* Author......: See docs/credits.txt
* License.....: MIT
*/

#ifndef _BITMAP_H
#define _BITMAP_H

#include <string.h>
#include "types.h"

int bitmap_ctx_init(bitmap_ctx_t   *bitmap_ctx, hashconfig_t   *hashconfig, hashes_t *hashes);
void bitmap_ctx_destroy(bitmap_ctx_t *bitmap_ctx);

#endif // _BITMAP_H
