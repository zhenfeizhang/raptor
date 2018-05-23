/******************************************************************************
 * NTRU Cryptography Reference Source Code submitting to NIST call for
 * proposals for post quantum cryptography
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity, with additional
 * codes from public domain.
 *
 ******************************************************************************/
/*
 * linkable_raptor.c
 *
 *  Created on: May 22, 2018
 *      Author: zhenfei
 */


#include "raptor.h"


int linkable_raptor_keygen(
    raptor_data     data,
    unsigned char   *sk,
    unsigned char   *ots_pk,        /* in       -   one time signature public key */
    unsigned char   *ots_sk)        /* in       -   one time signature secret key */
{

    /* generate raptor keys */
    if(raptor_keygen(data, sk)!=0)
    {
        printf("raptor key gen failed");
        return -1;
    }
    /* generate OTS keys */
    int             ret_val;
    if ( (ret_val = crypto_sign_keypair(ots_pk, ots_sk)) != 0) {
        printf("crypto_sign_keypair returned <%d>\n", ret_val);
        return -1;
    }
    /* generate masking matrix */
    int             i;
    unsigned char   seed[SEEDLEN];
    int64_t         mask[DIM];
    crypto_hash_sha512(seed, ots_pk, CRYPTO_PUBLICKEYBYTES);
    pol_unidrnd_with_seed(mask, DIM, PARAM_Q, seed, SEEDLEN);
    for (i=0; i<DIM; i++)
    {
        data.h[i] = (data.h[i] + mask[i])%PARAM_Q;
        if (data.h[i] <0)
            data.h[i] += PARAM_Q;
    }
    return 0;
}


int
linkable_raptor_sign(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    unsigned char       *sk,
    int64_t             *H,
    unsigned char       *ots_pk,
    unsigned char       *ots_sk,
    unsigned char       *ots_sm)
{


    /* generate the ring signature */
    raptor_sign(msg, msg_len, data, sk, H);

    /* build the buf that stores the ring sig */

    int                 i;
    unsigned char       *buf;
    int64_t             *ptr64;
    int                 buflen;
    unsigned long long  smlen;

    buflen  =   sizeof(int64_t)*DIM*NOU     /* b_i */
            +   sizeof(int64_t)*DIM*NOU*2   /* r_i */
            +   sizeof(int64_t)*DIM*NOU     /* h_i */
            +   CRYPTO_PUBLICKEYBYTES;      /* ots pk */

    buf =   malloc (buflen);

    if(!buf)
    {
        printf("memory error\n");
        return -1;
    }
    memset(buf, 0, buflen);
    for (i=0;i<NOU;i++)
    {
        ptr64   =   data[i].d;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4,    (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].r0;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+1,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].r1;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+2,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].h;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+3,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
    }
    memcpy(buf + sizeof(int64_t)*DIM*NOU *4, ots_pk, CRYPTO_PUBLICKEYBYTES);

    /* sign the buf */

    crypto_sign(ots_sm, &smlen, buf, buflen,  ots_sk);


    free(buf);
    return smlen;
}


int
linkable_raptor_verify(
    const unsigned char *msg,
    unsigned long long  mlen,
    raptor_data         *data,
    int64_t             *H,
    unsigned char       *ots_pk,
    unsigned char       *ots_sm,
    unsigned long long  ots_smlen)
{


    /* first check the ring signature */
    if (raptor_verify (msg, mlen, data, H)!=0)
        return -1;


    /* build the buf that stores the ring sig */
    int                 i;
    unsigned char       *buf;
    int64_t             *ptr64;
    int                 buflen;

    buflen  =   sizeof(int64_t)*DIM*NOU     /* b_i */
            +   sizeof(int64_t)*DIM*NOU*2   /* r_i */
            +   sizeof(int64_t)*DIM*NOU     /* h_i */
            +   CRYPTO_PUBLICKEYBYTES;      /* ots pk */
    buf     =   malloc (buflen);

    if(!buf)
    {
        printf("memory error\n");
        return -1;
    }
    memset(buf, 0, buflen);
    for (i=0;i<NOU;i++)
    {
        ptr64   =   data[i].d;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4,    (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].r0;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+1,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].r1;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+2,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
        ptr64   =   data[i].h;
        memcpy(buf+ sizeof(int64_t)*DIM*i*4+3,  (unsigned char *) ptr64, sizeof(int64_t)*DIM);
    }
    memcpy(buf + sizeof(int64_t)*DIM*NOU *4, ots_pk, CRYPTO_PUBLICKEYBYTES);

    /* verify the signature, store the recovered message in msg_rec */

    unsigned char       *msg_rec;
    unsigned long long  msglen;
    msg_rec =   malloc (ots_smlen);
    if(!msg_rec)
    {
        printf("memory error\n");
        return -1;
    }
    if (crypto_sign_open(msg_rec, &msglen, ots_sm, ots_smlen, ots_pk)!=0)
    {
        printf("invalid signature\n");
        return -1;
    }

    /* compare the store message with buf */

    if(msglen != buflen)
    {
        printf("invalid message length\n");
        return -1;
    }

    if(memcmp(buf,msg_rec, buflen)!=0)
    {
        printf("invalid recovered message\n");
        return -1;
    }

    free(buf);
    free(msg_rec);
    return 0;
}
