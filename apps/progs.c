/*
 * WARNING: do not edit!
 * Generated by apps/progs.pl
 *
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "progs.h"

FUNCTION functions[] = {
    {FT_general, "asn1parse", asn1parse_main, asn1parse_options, NULL},
    {FT_general, "ca", ca_main, ca_options, NULL},
#ifndef OPENSSL_NO_SOCK
    {FT_general, "ciphers", ciphers_main, ciphers_options, NULL},
#endif
#ifndef OPENSSL_NO_CMS
    {FT_general, "cms", cms_main, cms_options, NULL},
#endif
    {FT_general, "crl", crl_main, crl_options, NULL},
    {FT_general, "crl2pkcs7", crl2pkcs7_main, crl2pkcs7_options, NULL},
    {FT_general, "dgst", dgst_main, dgst_options, NULL},
#if !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "dhparam", dhparam_main, dhparam_options, "pkeyparam"},
#endif
#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "dsa", dsa_main, dsa_options, "pkey"},
#endif
#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "dsaparam", dsaparam_main, dsaparam_options, "pkeyparam"},
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "ec", ec_main, ec_options, "pkey"},
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "ecparam", ecparam_main, ecparam_options, "pkeyparam"},
#endif
    {FT_general, "enc", enc_main, enc_options, NULL},
#ifndef OPENSSL_NO_ENGINE
    {FT_general, "engine", engine_main, engine_options, NULL},
#endif
    {FT_general, "errstr", errstr_main, errstr_options, NULL},
    {FT_general, "fipsinstall", fipsinstall_main, fipsinstall_options, NULL},
#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    {FT_general, "gendsa", gendsa_main, gendsa_options, "genpkey"},
#endif
    {FT_general, "genpkey", genpkey_main, genpkey_options, NULL},
#ifndef OPENSSL_NO_RSA
    {FT_general, "genrsa", genrsa_main, genrsa_options, NULL},
#endif
    {FT_general, "help", help_main, help_options, NULL},
    {FT_general, "info", info_main, info_options, NULL},
    {FT_general, "kdf", kdf_main, kdf_options, NULL},
    {FT_general, "list", list_main, list_options, NULL},
    {FT_general, "mac", mac_main, mac_options, NULL},
    {FT_general, "nseq", nseq_main, nseq_options, NULL},
#ifndef OPENSSL_NO_OCSP
    {FT_general, "ocsp", ocsp_main, ocsp_options, NULL},
#endif
    {FT_general, "passwd", passwd_main, passwd_options, NULL},
#ifndef OPENSSL_NO_DES
    {FT_general, "pkcs12", pkcs12_main, pkcs12_options, NULL},
#endif
    {FT_general, "pkcs7", pkcs7_main, pkcs7_options, NULL},
    {FT_general, "pkcs8", pkcs8_main, pkcs8_options, NULL},
    {FT_general, "pkey", pkey_main, pkey_options, NULL},
    {FT_general, "pkeyparam", pkeyparam_main, pkeyparam_options, NULL},
    {FT_general, "pkeyutl", pkeyutl_main, pkeyutl_options, NULL},
    {FT_general, "prime", prime_main, prime_options, NULL},
    {FT_general, "provider", provider_main, provider_options, NULL},
    {FT_general, "rand", rand_main, rand_options, NULL},
    {FT_general, "rehash", rehash_main, rehash_options, NULL},
    {FT_general, "req", req_main, req_options, NULL},
    {FT_general, "rsa", rsa_main, rsa_options, NULL},
#ifndef OPENSSL_NO_RSA
    {FT_general, "rsautl", rsautl_main, rsautl_options, NULL},
#endif
#ifndef OPENSSL_NO_SOCK
    {FT_general, "s_client", s_client_main, s_client_options, NULL},
#endif
#ifndef OPENSSL_NO_SOCK
    {FT_general, "s_server", s_server_main, s_server_options, NULL},
#endif
#ifndef OPENSSL_NO_SOCK
    {FT_general, "s_time", s_time_main, s_time_options, NULL},
#endif
    {FT_general, "sess_id", sess_id_main, sess_id_options, NULL},
    {FT_general, "smime", smime_main, smime_options, NULL},
    {FT_general, "speed", speed_main, speed_options, NULL},
    {FT_general, "spkac", spkac_main, spkac_options, NULL},
#ifndef OPENSSL_NO_SRP
    {FT_general, "srp", srp_main, srp_options, NULL},
#endif
    {FT_general, "storeutl", storeutl_main, storeutl_options, NULL},
#ifndef OPENSSL_NO_TS
    {FT_general, "ts", ts_main, ts_options, NULL},
#endif
    {FT_general, "verify", verify_main, verify_options, NULL},
    {FT_general, "version", version_main, version_options, NULL},
    {FT_general, "x509", x509_main, x509_options, NULL},
#ifndef OPENSSL_NO_MD2
    {FT_md, "md2", dgst_main, NULL, NULL},
#endif
#ifndef OPENSSL_NO_MD4
    {FT_md, "md4", dgst_main, NULL, NULL},
#endif
    {FT_md, "md5", dgst_main, NULL, NULL},
#ifndef OPENSSL_NO_GOST
    {FT_md, "gost", dgst_main, NULL, NULL},
#endif
    {FT_md, "sha1", dgst_main, NULL, NULL},
    {FT_md, "sha224", dgst_main, NULL, NULL},
    {FT_md, "sha256", dgst_main, NULL, NULL},
    {FT_md, "sha384", dgst_main, NULL, NULL},
    {FT_md, "sha512", dgst_main, NULL, NULL},
    {FT_md, "sha512-224", dgst_main, NULL, NULL},
    {FT_md, "sha512-256", dgst_main, NULL, NULL},
    {FT_md, "sha3-224", dgst_main, NULL, NULL},
    {FT_md, "sha3-256", dgst_main, NULL, NULL},
    {FT_md, "sha3-384", dgst_main, NULL, NULL},
    {FT_md, "sha3-512", dgst_main, NULL, NULL},
    {FT_md, "shake128", dgst_main, NULL, NULL},
    {FT_md, "shake256", dgst_main, NULL, NULL},
#ifndef OPENSSL_NO_MDC2
    {FT_md, "mdc2", dgst_main, NULL, NULL},
#endif
#ifndef OPENSSL_NO_RMD160
    {FT_md, "rmd160", dgst_main, NULL, NULL},
#endif
#ifndef OPENSSL_NO_BLAKE2
    {FT_md, "blake2b512", dgst_main, NULL, NULL},
#endif
#ifndef OPENSSL_NO_BLAKE2
    {FT_md, "blake2s256", dgst_main, NULL, NULL},
#endif
#ifndef OPENSSL_NO_SM3
    {FT_md, "sm3", dgst_main, NULL, NULL},
#endif
    {FT_cipher, "aes-128-cbc", enc_main, enc_options, NULL},
    {FT_cipher, "aes-128-ecb", enc_main, enc_options, NULL},
    {FT_cipher, "aes-192-cbc", enc_main, enc_options, NULL},
    {FT_cipher, "aes-192-ecb", enc_main, enc_options, NULL},
    {FT_cipher, "aes-256-cbc", enc_main, enc_options, NULL},
    {FT_cipher, "aes-256-ecb", enc_main, enc_options, NULL},
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-ctr", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-cfb1", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-128-cfb8", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-ctr", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-cfb1", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-192-cfb8", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-ctr", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-cfb1", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_ARIA
    {FT_cipher, "aria-256-cfb8", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-128-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-128-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-192-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-192-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-256-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAMELLIA
    {FT_cipher, "camellia-256-ecb", enc_main, enc_options, NULL},
#endif
    {FT_cipher, "base64", enc_main, enc_options, NULL},
#ifdef ZLIB
    {FT_cipher, "zlib", enc_main, enc_options, NULL},
#endif
#ifdef BROTLI
    {FT_cipher, "brotli", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des3", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "desx", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_IDEA
    {FT_cipher, "idea", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SEED
    {FT_cipher, "seed", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC4
    {FT_cipher, "rc4", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC4
    {FT_cipher, "rc4-40", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_BF
    {FT_cipher, "bf", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC5
    {FT_cipher, "rc5", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede3", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede3-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede3-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_DES
    {FT_cipher, "des-ede3-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_IDEA
    {FT_cipher, "idea-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_IDEA
    {FT_cipher, "idea-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_IDEA
    {FT_cipher, "idea-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_IDEA
    {FT_cipher, "idea-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SEED
    {FT_cipher, "seed-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SEED
    {FT_cipher, "seed-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SEED
    {FT_cipher, "seed-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SEED
    {FT_cipher, "seed-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-64-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC2
    {FT_cipher, "rc2-40-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_BF
    {FT_cipher, "bf-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_BF
    {FT_cipher, "bf-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_BF
    {FT_cipher, "bf-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_BF
    {FT_cipher, "bf-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast5-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast5-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast5-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast5-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_CAST
    {FT_cipher, "cast-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC5
    {FT_cipher, "rc5-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC5
    {FT_cipher, "rc5-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC5
    {FT_cipher, "rc5-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_RC5
    {FT_cipher, "rc5-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SM4
    {FT_cipher, "sm4-cbc", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SM4
    {FT_cipher, "sm4-ecb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SM4
    {FT_cipher, "sm4-cfb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SM4
    {FT_cipher, "sm4-ofb", enc_main, enc_options, NULL},
#endif
#ifndef OPENSSL_NO_SM4
    {FT_cipher, "sm4-ctr", enc_main, enc_options, NULL},
#endif
    {0, NULL, NULL, NULL, NULL}
};
