/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * raptor.h
 *
 *  Created on: May 14, 2018
 *      Author: zhenfei
 */

#ifndef RAPTOR_H_
#define RAPTOR_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng/rng.h"
#include "rng/crypto_hash_sha512.h"
#include "rng/fastrandombytes.h"
#include "falcon/falcon.h"
#include "falcon/api.h"
#include "falcon/internal.h"
#include "poly.h"
#include "param.h"


/* raptor structures */
typedef struct _raptor_data_ raptor_data;
struct _raptor_data_ {

    int64_t             *c;
    int64_t             *d;
    int64_t             *h;
    int64_t             *r0;
    int64_t             *r1;

};

typedef struct _raptor_skey_ raptor_sk;
struct _raptor_skey_ {

    int64_t             *f;
    int64_t             *g;
    int64_t             *F;
    int64_t             *G;
};



int
raptor_keygen(
    raptor_data         data,
    unsigned char       *sk);

int
raptor_fake_keygen(
    raptor_data         data);


int
raptor_sign(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    unsigned char       *sk,
    int64_t             *H);


int
raptor_verify(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    int64_t             *H);

int
linkable_raptor_sign(
    const unsigned char *msg,           /* in       -   msg to be signed */
    unsigned long long  msg_len,
    raptor_data         *data,          /* in/out   -   list of public keys and associated data */
    unsigned char       *sk,            /* in       -   secret key */
    int64_t             *H,             /* in       -   public matrix */
    unsigned char       *ots_pk,        /* in       -   one time signature public key */
    unsigned char       *ots_sk,        /* in       -   one time signature secret key */
    unsigned char       *ots_sm);       /* out      -   one time signature */
                                        /* return   -   the length of signature */

int
linkable_raptor_verify(
    const unsigned char *msg,           /* in       -   msg signed */
    unsigned long long  msg_len,
    raptor_data         *data,          /* in       -   list of public keys and associated data */
    int64_t             *H,             /* in       -   public matrix */
    unsigned char       *ots_pk,        /* in       -   one time signature public key */
    unsigned char       *ots_sm,        /* in       -   one time signature */
    unsigned long long  ots_mlen);      /* in       -   the length of signature */

void
form_digest(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    unsigned char       *out);

int
falcon_sign_with_u(
    falcon_sign         *fs,
    int64_t             *u,
    int64_t             *r0,
    int64_t             *r1);

void
extract_pkey(
    unsigned char       *falcon_pk,
    int64_t             *h);

void
extract_skey(
    unsigned char       *falcon_sk,
    int64_t             *f,
    int64_t             *g,
    int64_t             *F,
    int64_t             *G);


void print_raptor_data(
    raptor_data        data);
#endif /* RAPTOR_H_ */
