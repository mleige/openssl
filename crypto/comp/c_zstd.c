/*
 * Copyright 1998-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Uses zstd compression library from https://github.com/facebook/zstd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include "internal/comp.h"
#include <openssl/err.h>
#include "internal/bio.h"
#include "comp_local.h"

COMP_METHOD *COMP_zstd(void);

static COMP_METHOD zstd_method_nozstd = {
    NID_undef,
    "(undef)",
    NULL,
    NULL,
    NULL,
    NULL,
};

#ifndef ZSTD
# undef ZSTD_SHARED
#else

# include <zstd/zstd.h>

# ifdef ZSTD_H_235446
#  error WRONG ZSTD?
# endif

/* memory allocations functions for zstd initialisation */
static void *zstd_alloc(void *opaque, size_t size)
{
    return OPENSSL_zalloc(size);
}

static void zstd_free(void *opaque, void *address)
{
    return OPENSSL_free(address);
}

static ZSTD_customMem zstd_mem_funcs = {
    zstd_alloc,
    zstd_free,
    NULL
};

/*
 * When OpenSSL is built on Windows, we do not want to require that
 * the LIBZSTD.DLL be available in order for the OpenSSL DLLs to
 * work.  Therefore, all ZSTD routines are loaded at run time
 * and we do not link to a .LIB file when ZSTD_SHARED is set.
 */
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#  include <windows.h>
# endif                         /* !(OPENSSL_SYS_WINDOWS ||
                                 * OPENSSL_SYS_WIN32) */

# ifdef ZSTD_SHARED
#  include "internal/dso.h"

/* Function pointers */
typedef ZSTD_CStream* (*createCStream_advanced_ft)(ZSTD_customMem);
typedef size_t (*initCStream_ft)(ZSTD_CStream*, int);
typedef size_t (*freeCStream_ft)(ZSTD_CStream*);
typedef size_t (*compressStream2_ft)(ZSTD_CCtx*, ZSTD_outBuffer*, ZSTD_inBuffer*, ZSTD_EndDirective);
typedef size_t (*flushStream_ft)(ZSTD_CStream*, ZSTD_outBuffer*);
typedef size_t (*endStream_ft)(ZSTD_CStream*, ZSTD_outBuffer*);
typedef size_t (*compress_ft)(void*, size_t, const void*, size_t, int);
typedef ZSTD_DStream* (*createDStream_advanced_ft)(ZSTD_customMem);
typedef size_t (*initDStream_ft)(ZSTD_DStream*);
typedef size_t (*freeDStream_ft)(ZSTD_DStream*);
typedef size_t (*decompressStream_ft)(ZSTD_DStream*, ZSTD_outBuffer*, ZSTD_inBuffer*);
typedef size_t (*decompress_ft)(void*, size_t, const void*, size_t);
typedef unsigned (*isError_ft)(size_t);

static createCStream_advanced_ft p_createCStream_advanced = NULL;
static initCStream_ft p_initCStream = NULL;
static freeCStream_ft p_freeCStream = NULL;
static compressStream2_ft p_compressStream2 = NULL;
static flushStream_ft p_flushStream = NULL;
static endStream_ft p_endStream = NULL;
static compress_ft p_compress = NULL;
static createDStream_advanced_ft p_createDStream_advanced = NULL;
static initDStream_ft p_initDStream = NULL;
static freeDStream_ft p_freeDStream = NULL;
static decompressStream_ft p_decompressStream = NULL;
static decompress_ft p_decompress = NULL;
static isError_ft p_isError = NULL;

static DSO *zstd_dso = NULL;

#  define ZSTD_createCStream_advanced p_createCStream_advanced
#  define ZSTD_initCStream p_initCStream
#  define ZSTD_freeCStream p_freeCStream
#  define ZSTD_compressStream2 p_compressStream2
#  define ZSTD_flushStream p_flushStream
#  define ZSTD_endStream p_endStream
#  define ZSTD_compress p_compress
#  define ZSTD_createDStream_advanced p_createDStream_advanced
#  define ZSTD_initDStream p_initDStream
#  define ZSTD_freeDStream p_freeDStream
#  define ZSTD_decompressStream p_decompressStream
#  define ZSTD_decompress p_decompress
#  define ZSTD_isError p_isError

# endif /* ifdef ZSTD_SHARED */

struct zstd_state {
    ZSTD_CStream *compressor;
    ZSTD_DStream *decompressor;
};

static int zstd_stateful_init(COMP_CTX *ctx)
{
    struct zstd_state *state = OPENSSL_zalloc(sizeof(*state));

    if (state == NULL)
        goto err;

    state->compressor = ZSTD_createCStream_advanced(&zstd_mem_funcs);
    if (state->compressor == NULL)
        goto err;
    ZSTD_initCStream(state->compressor, ZSTD_CLEVEL_DEFAULT);

    state->decompressor = ZSTD_createDStream_advanced(&zstd_mem_funcs);
    if (state->decompressor == NULL)
        goto err;
    ZSTD_initDStream(state->decompressor);

    ctx->data = state;
    return 1;
 err:
    ZSTD_freeCStream(state->compressor);
    ZSTD_freeDstream(state->decompressor);
    OPENSSL_free(state);
    return 0;
}

static void zstd_stateful_finish(COMP_CTX *ctx)
{
    struct zstd_state *state = ctx->data;

    if (state != NULL) {
        ZSTD_freeCStream(state->compressor);
        ZSTD_freeDstream(state->decompressor);
        OPENSSL_free(state);
        ctx->data = NULL;
    }
}

static int zstd_stateful_compress_block(COMP_CTX *ctx, unsigned char *out,
                                        unsigned int olen, unsigned char *in,
                                        unsigned int ilen)
{
    ZSTD_inBuffer inbuf;
    ZSTD_outBuffer outbuf;
    size_t ret;
    struct zstd_state *state = ctx->data;

    inbuf.src = in;
    inbuf.size = ilen;
    inbuf.pos = 0;
    outbuf.dst = out;
    outbuf.size = olen;
    outbuf.pos = 0;
    
    if (state == NULL)
        return -1;

    /* If input length is zero, end the stream/frame ? */
    if (ilen == 0) {
        ret = ZSTD_endStream(state->compressor, &outbuf);
        if (ZSTD_isError(ret))
            return -1;
        return outbuf.pos;
    }

    /*
     * The finish API does not provide a final output buffer,
     * so each compress operation has to be ended, if all
     * the input data can't be accepted, or there is more output,
     * this has to be considered an error, since there is no more
     * output buffer space.
     */
    do {
        ret = ZSTD_compressStream2(state->compressor, &outbuf, &inbuf, ZSTD_e_continue);
        if (ZSTD_isError(ret))
            return -1;
        /* do I need to check for ret == 0 ? */
    } while (inbuf.pos < inbuf.out);

    /* Did not consume all the data */
    if (inbuf.pos < inbuf.out)
        return -1;

    ret = ZSTD_flushStream(state->compressor, &outbuf);
    if (ZSTD_isError(ret))
        return -1;

    return outbuf.pos;
}

static int zstd_stateful_expand_block(COMP_CTX *ctx, unsigned char *out,
                                      unsigned int olen, unsigned char *in,
                                      unsigned int ilen)
{
    ZSTD_inBuffer inbuf;
    ZSTD_outBuffer outbuf;
    size_t ret;
    struct zstd_state *state = ctx->data;

    inbuf.src = in;
    inbuf.size = ilen;
    inbuf.pos = 0;
    outbuf.dst = out;
    outbuf.size = olen;
    outbuf.pos = 0;
    
    if (state == NULL)
        return -1;

    if (ilen == 0)
        return 0;

    do {
        ret = ZSTD_decompressStream(state->decompressor, &outbuf, &inbuf);
        if (ZSTD_isError(ret))
            return -1;
        /* If we completed a frame, and there's more data, try again */
    } while (ret == 0 && inbuf.pos < inbuf.out);

    /* Did not consume all the data */
    if (inbuf.pos < inbuf.out)
        return -1;

    return outbuf.pos;
}


static COMP_METHOD zstd_stateful_method = {
    NID_zstd,
    LN_zstd,
    zstd_stateful_init,
    zstd_stateful_finish,
    zstd_stateful_compress_block,
    zstd_stateful_expand_block
};


static int zstd_oneshot_init(COMP_CTX *ctx)
{
    return 1;
}

static void zstd_oneshot_finish(COMP_CTX *ctx)
{
}

static int zstd_oneshot_compress_block(COMP_CTX *ctx, unsigned char *out,
                                         unsigned int olen, unsigned char *in,
                                         unsigned int ilen)
{
    size_t out_size;

    if (ilen == 0)
        return 0;

    /* Note: uses STDLIB memory allocators */
    out_size = ZSTD_compress(out, olen, in, ilen, ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(out_size))
        return -1;

    return out_size;
}

static int zstd_oneshot_expand_block(COMP_CTX *ctx, unsigned char *out,
                                       unsigned int olen, unsigned char *in,
                                       unsigned int ilen)
{
    size_t out_size;

    if (ilen == 0)
        return 0;

    /* Note: uses STDLIB memory allocators */
    out_size = ZSTD_decompress(out, olen, in, ilen);
    if (ZSTD_isError(out_size))
        return -1;

    return out_size;
}

static COMP_METHOD zstd_oneshot_method = {
    NID_zstd,
    LN_zstd,
    zstd_oneshot_init,
    zstd_oneshot_finish,
    zstd_oneshot_compress_block,
    zstd_oneshot_expand_block
};

static int comp_zstd_init_int(void)
{
# ifdef ZSTD_SHARED
#  if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#   define LIBZSTD "LIBZSTD"
#  elif defined(OPENSSL_SYS_VMS)
#   define LIBZSTD "LIBZSTD"
#  else
#   define LIBZSTD  "zstd"
#  endif

    if (zstd_dso == NULL)
        zstd_encode_dso = DSO_load(NULL, LIBZSTD, NULL, 0);
    if (zstd_dso != NULL) {
        p_createCStream_advanced = (createCStream_advanced_ft)DSO_bind_func(zstd_dso, "ZSTD_createCStream_advanced");
        p_initCStream = (initCStream_ft)DSO_bind_func(zstd_dso, "ZSTD_initCStream");
        p_freeCStream = (freeCStream_ft)DSO_bind_func(zstd_dso, "ZSTD_freeCStream");
        p_compressStream2 = (compressStream2_ft)DSO_bind_func(zstd_dso, "ZSTD_compressStream2");
        p_flushStream = (flushStream_ft)DSO_bind_func(zstd_dso, "ZSTD_flushStream");
        p_endStream = (endStream_ft)DSO_bind_func(zstd_dso, "ZSTD_endStream");
        p_compress = (compress_ft)DSO_bind_func(zstd_dso, "ZSTD_compress");
        p_createDStream_advanced = (createDStream_advanced_ft)DSO_bind_func(zstd_dso, "ZSTD_createDStream_advanced");
        p_initDStream = (initDStream_ft)DSO_bind_func(zstd_dso, "ZSTD_initDStream");
        p_freeDStream = (freeDStream_ft)DSO_bind_func(zstd_dso, "ZSTD_freeDStream");
        p_decompressStream = (decompressStream_ft)DSO_bind_func(zstd_dso, "ZSTD_decompressStream");
        p_decompress = (decompress_ft)DSO_bind_func(zstd_dso, "ZSTD_decompress");
        p_isError = (isError_ft)DSO_bind_func(zstd_dso, "ZSTD_isError");
    }

    if (p_createCStream_advanced == NULL || p_initCStream == NULL || p_freeCStream == NULL
            || p_compressStream2 == NULL || p_flushStream == NULL || p_endStream == NULL
            || p_compress == NULL || p_createDStream_advanced == NULL || p_initDStream == NULL
            || p_freeDStream == NULL || p_decompressStream == NULL || p_decompress == NULL
            || p_isError == NULL
            || !OPENSSL_init_crypo(OPENSSL_INIT_ZSTD, NULL)) {
        comp_zstd_cleanup_int();
        return 0;
    }
# endif
    return 1;
}
#endif /* ifndef ZSTD / else */

COMP_METHOD *COMP_zstd(void)
{
    COMP_METHOD *meth = &zstd_method_nozstd;

#ifdef ZSTD
    if (comp_zstd_init_int())
        meth = &zstd_stateful_method;
#endif
    return meth;
}

COMP_METHOD *COMP_zstd_oneshot(void)
{
    COMP_METHOD *meth = &zstd_method_nozstd;

#ifdef ZSTD
    if (comp_zstd_init_int())
        meth = &zstd_oneshot_method;
#endif
    return meth;
}

void comp_zstd_cleanup_int(void)
{
#ifdef ZSTD_SHARED
    DSO_free(zstd_dso);
    zstd_dso = NULL;
    p_createCStream_advanced = NULL;
    p_initCStream = NULL;
    p_freeCStream = NULL;
    p_compressStream2 = NULL;
    p_flushStream = NULL;
    p_endStream = NULL;
    p_compress = NULL;
    p_createDStream_advanced = NULL;
    p_initDStream = NULL;
    p_freeDStream = NULL;
    p_decompressStream = NULL;
    p_decompress = NULL;
    p_isError = NULL;
#endif
}

#ifdef ZSTD

/* Zstd-based compression/decompression filter BIO */

typedef struct {
    struct { /* input structure */
        ZSTD_DStream *state;
        ZSTD_inBuffer inbuf;
        size_t bufsize;
    } decompress;
    struct { /* output structure */
        ZSTD_CStream *state;
        ZSTD_outBuffer outbuf;
        size_t bufsize;
        size_t write_pos;
    } compress;
} BIO_ZSTD_CTX;

# define ZSTD_DEFAULT_BUFSIZE 1024

static int bio_zstd_new(BIO *bi);
static int bio_zstd_free(BIO *bi);
static int bio_zstd_read(BIO *b, char *out, int outl);
static int bio_zstd_write(BIO *b, const char *in, int inl);
static long bio_zstd_ctrl(BIO *b, int cmd, long num, void *ptr);
static long bio_zstd_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);

static const BIO_METHOD bio_meth_zstd = {
    BIO_TYPE_COMP,
    "zstd",
    /* TODO: Convert to new style write function */
    bwrite_conv,
    bio_zstd_write,
    /* TODO: Convert to new style read function */
    bread_conv,
    bio_zstd_read,
    NULL,                      /* bio_zstd_puts, */
    NULL,                      /* bio_zstd_gets, */
    bio_zstd_ctrl,
    bio_zstd_new,
    bio_zstd_free,
    bio_zstd_callback_ctrl
};

const BIO_METHOD *BIO_f_zstd(void)
{
    return &bio_meth_zstd;
}

static int bio_zstd_new(BIO *bi)
{
    BIO_ZSTD_CTX *ctx;

# ifdef ZSTD_SHARED
    (void)COMP_zstd();
    if (zstd_dso == NULL) {
        COMPerr(COMP_F_BIO_ZSTD_NEW, COMP_R_ZSTD_NOT_SUPPORTED);
        return 0;
    }
# endif
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        COMPerr(COMP_F_BIO_ZSTD_NEW, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->decompress.state =  ZSTD_createDStream_advanced(&zstd_mem_funcs);
    if (ctx->decompress.state == NULL)
        goto err;
    ZSTD_initDStream(ctx->decompress.state);
    ctx->decompress.bufsize = ZSTD_DStreamInSize();

    ctx->compress.state = ZSTD_createCStream_advanced(&zstd_mem_funcs);
    if (ctx->compress.state == NULL)
        goto err;
    ZSTD_initCStream(ctx->compress.state, ZSTD_CLEVEL_DEFAULT);
    ctx->compress.bufsize = ZSTD_CStreamInSize();

    BIO_set_init(bi, 1);
    BIO_set_data(bi, ctx);

    return 1;
 err:
    COMPerr(COMP_F_BIO_ZSTD_NEW, ERR_R_MALLOC_FAILURE);
    ZSTD_freeDStream(ctx->decompress.state);
    ZSTD_freeCStream(ctx->compress.state);
    OPENSSL_free(ctx);
    return 0;
}

static int bio_zstd_free(BIO *bi)
{
    BIO_ZSTD_CTX *ctx;

    if (bi == NULL)
        return 0;

    ctx = BIO_get_data(bi);
    if (ctx != NULL) {
        ZSTD_freeDStream(ctx->decompress.state);
        OPENSSL_free(ctx->decompress.inbuf.src);
        ZSTD_freeCStream(ctx->compress.state);
        OPENSSL_free(ctx->compress.outbuf.dst);
        OPENSSL_free(ctx);
    }
    BIO_set_data(bi, NULL);
    BIO_set_init(bi, 0);

    return 1;
}

static int bio_zstd_read(BIO *b, char *out, int outl)
{
    BIO_ZSTD_CTX *ctx;
    size_t zret;
    int ret;
    ZSTD_outBuffer outBuf;
    BIO *next = BIO_next(b);

    if (out == NULL || outl == 0)
        return 0;

    ctx = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (ctx->decompress.inbuf.src == NULL) {
        ctx->decompress.inbuf.src = OPENSSL_malloc(ctx->decompress.bufsize);
        if (ctx->decompress.inbuf.src == NULL) {
            COMPerr(COMP_F_BIO_ZSTD_READ, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ctx->decompress.inbuf.size = 0;
        ctx->decompress.inbuf.pos = 0;
    }

    /* Copy output data directly to supplied buffer */
    outBuf.dst = (unsigned char *)out;
    outBuf.size = (size_t)outl;
    outBuf.pos = 0;
    for (;;) {
        /* Decompress while data available */
        while (ctx->decompress.inbuf.pos < ctx->decompress.inbuf.size) {
            zret = ZSTD_decompressStream(ctx->decompress.state, &outBuf, &ctx->decompress.in);
            if (ZSTD_isError(zret)) {
                COMPerr(COMP_F_BIO_ZSTD_READ, COMP_R_ZSTD_DECOMPRESS_ERROR);
                ERR_add_error_data(1, ZSTD_getErrorName(zret));
                return -1;
            }
            /* No more output space */
            if (outBuf.pos == outBuf.size)
                return outBuf.pos;
        }

        /* If EOF ?? return 0 */

        /* Did not read in all the data? */
        /* DO WE NEED TO HANDLE THIS */
        if (ctx->decompress.inbuf.pos < ctx->decompress.inbuf.size) {
            COMPerr(COMP_F_BIO_ZSTD_READ, COMP_R_ZSTD_DECOMPRESS_ERROR);
            return -1;
        }

        /*
         * No data in input buffer try to read some in, if an error then
         * return the total data read.
         */
        ret = BIO_read(next, ctx->decompress.inbuf.src, ctx->decompress.bufsize);
        if (ret <= 0) {
            BIO_copy_next_retry(b);
            if (ret < 0 && outBuf.pos == 0)
                return ret;
            return outBuf.pos;
        }
        ctx->decompress.inbuf.size = ret;
        ctx->decompress.inbuf.pos = 0;
    }
}

static int bio_zstd_write(BIO *b, const char *in, int inl)
{
    BIO_ZSTD_CTX *ctx;
    size_t zret;
    ZSTD_inBuffer inBuf;
    int ret;
    BIO *next = BIO_next(b);

    if (in == NULL || inl == 0)
        return 0;

    ctx = BIO_get_data(b);
    if (ctx->encode.done)
        return 0;

    BIO_clear_retry_flags(b);
    if (ctx->compress.outbuf.dst == NULL) {
        ctx->compress.outbuf.dst = OPENSSL_malloc(ctx->compress.bufsize);
        if (ctx->compress.outbuf.dst == NULL) {
            COMPerr(COMP_F_BIO_ZSTD_WRITE, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ctx->compress.outbuf.size = 0;
        ctx->compress.outbuf.pos = 0;
        ctx->compress.write_pos = 0;
    }
    /* Obtain input data directly from supplied buffer */
    inBuf.src = (unsigned char *)in;
    inBuf.size = inl;
    inBuf.pos = 0;
    for (;;) {
        /* If data in output buffer write it first */
        while (ctx->compress.write_pos < ctx->compress.outbuf.pos) {
            ret = BIO_write(next, ctx->compress.buf.dst + ctx->compress.write_pos,
                            ctx->compress.outbuf.pos - ctx->compress.write_pos);
            if (ret <= 0) {
                BIO_copy_next_retry(b);
                if (ret < 0 && inBuf.pos == 0)
                    return ret;
                return inBuf.pos;
            }
            ctx->compress.write_pos += ret;
        }

        /* Have we consumed all supplied data? */
        if (inBuf.pos == inBuf.size)
            return inBuf.pos;

        /* Reset buffer */
        ctx->compress.buf.pos = 0;
        ctx->compress.buf.size = ctx->compress.bufsize;
        ctx->compress.write_pos = 0;
        /* Compress some more */
        zret = ZSTD_compressStream2(ctx->compress.state, &ctx->compress.buf, &inBuf, ZSTD_e_continue);
        if (ZSTD_isError(zret)) {
            COMPerr(COMP_F_BIO_ZSTD_WRITE, COMP_R_ZSTD_COMPRESS_ERROR);
            ERR_add_error_data(1, ZSTD_getErrorName(zret));
            return 0;
        }
    }
}

static int bio_zstd_flush(BIO *b)
{
    BIO_ZSTD_CTX *ctx;
    size_t zret;
    int ret;
    BIO *next = BIO_next(b);

    ctx = BIO_get_data(b);

    /* If no data written or already flush show success */
    if (ctx->compress.buf.dst == NULL)
        return 1;

    BIO_clear_retry_flags(b);
    /* No more input data */
    ctx->encode.next_in = NULL;
    ctx->encode.avail_in = 0;
    for (;;) {
        /* If data in output buffer write it first */
        while (ctx->compress.write_pos < ctx->compress.outbuf.pos) {
            ret = BIO_write(next, ctx->compress.buf.dst + ctx->compress.write_pos,
                            ctx->compress.outbuf.pos - ctx->compress.write_pos);
            if (ret <= 0) {
                BIO_copy_next_retry(b);
                return ret;
            }
            ctx->compress.write_pos += ret;
        }

        /* Reset buffer */
        ctx->compress.buf.pos = 0;
        ctx->compress.buf.size = ctx->compress.bufsize;
        ctx->compress.write_pos = 0;
        /* Compress some more */
        zret = ZSTD_flushStream(ctx->compress.state, &ctx->compress.buf);
        if (ZSTD_isError(zret)) {
            COMPerr(COMP_F_BIO_ZSTD_FLUSH, COMP_R_ZSTD_DECODE_ERROR);
            ERR_add_error_data(1, ZSTD_getErrorName(zret));
            return 0;
        }
    }
}

static long bio_zstd_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO_ZSTD_CTX *ctx;
    int ret, *ip;
    size_t ibs, obs;
    BIO *next = BIO_next(b);

    if (next == NULL)
        return 0;
    ctx = BIO_get_data(b);
    switch (cmd) {

    case BIO_CTRL_RESET:
        ctx->compress.write_pos = 0;
        ctx->compress.
        ret = 1;
        break;

    case BIO_CTRL_FLUSH:
        ret = bio_zstd_flush(b);
        if (ret > 0)
            ret = BIO_flush(next);
        break;

    case BIO_C_SET_BUFF_SIZE:
        ibs = ctx->decompress.bufsize;
        obs = ctx->compress.bufsize;
        if (ptr != NULL) {
            ip = ptr;
            if (*ip == 0)
                ibs = (size_t)num;
            else
                obs = (size_t)num;
        } else {
            obs = ibs = (size_t)num;
        }

        if (ibs != ctx->decompress.bufsize) {
            OPENSSL_free(ctx->decompress.inbuf.src);
            ctx->decompress.inbuf.src = NULL
            ctx->decompress.bufsize = ibs;
        }

        if (obs != ctx->compress.bufsize) {
            OPENSSL_free(ctx->compress.outbuf.dst);
            ctx->compress.outbuf.dst = NULL;
            ctx->compress.bufsize = obs;
        }
        ret = 1;
        break;

    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(next, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;

    }

    return ret;
}

static long bio_zstd_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)
{
    BIO *next = BIO_next(b);
    if (next == NULL)
        return 0;
    return BIO_callback_ctrl(next, cmd, fp);
}

#endif
