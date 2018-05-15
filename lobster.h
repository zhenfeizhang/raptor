/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * lobster.h
 *
 *  Created on: May 14, 2018
 *      Author: zhenfei
 */

#ifndef LOBSTER_H_
#define LOBSTER_H_

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



typedef struct _lobster_data_ lobster_data;
struct _lobster_data_ {

    int64_t             *c;
    int64_t             *d;
    int64_t             *h;
    int64_t             *r0;
    int64_t             *r1;
    int64_t             *B;
    unsigned char       *seedB;
};

typedef struct _lobster_skey_ lobster_sk;
struct _lobster_skey_ {

    int64_t             *f;
    int64_t             *g;
    int64_t             *F;
    int64_t             *G;
};


int
lobster_keygen(
    lobster_data        data,
    unsigned char       *sk);

int
lobster_fake_keygen(
    lobster_data        data);


int
lobster_sign(
    const unsigned char *msg,
    unsigned long long  msg_len,
    lobster_data        *data,
    unsigned char       *sk);


int
lobster_verify(
    const unsigned char *msg,
    unsigned long long  msg_len,
    lobster_data        *data);


void
form_digest(
    const unsigned char *msg,
    unsigned long long  msg_len,
    lobster_data        *data,
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


void print_lobster_data(
    lobster_data        data);
#endif /* LOBSTER_H_ */
