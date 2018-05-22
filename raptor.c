/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * raptor.c
 *
 *  Created on: May 14, 2018
 *      Author: zhenfei
 */


#include "raptor.h"


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
raptor_sign(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    unsigned char       *sk,
    int64_t             *H)
{
    int             i,j;
    int64_t         *tmp1, *tmp2, *u;
    char            tmpchar;
    unsigned char   *seed;
    unsigned char   *hashdig;
    tmp1    = malloc(sizeof(int64_t)*DIM);
    tmp2    = malloc(sizeof(int64_t)*DIM);
    u       = malloc(sizeof(int64_t)*DIM);
    hashdig = malloc(64);
    seed    = malloc(SEEDLEN);
    if(!seed)
    {
        printf("memory error\n");
        return -1;
    }

    /*
     * for the rest of the users except the signer
     */
    for(i=0;i<NOU-1;i++)
    {

        /* generate the random small polynomials */
        DGS(data[i].r0, DIM, SIGMA);
        DGS(data[i].r1, DIM, SIGMA);
        binary_poly_gen(data[i].d, DIM);

        /* c = dH+r0+r1*h*/
        ring_mul(tmp1, data[i].d, H, DIM);
        ring_mul(tmp2, data[i].h, data[i].r1, DIM);
        for (j=0;j<DIM;j++)
        {
            data[i].c[j] = (tmp1[j]+tmp2[j]+data[i].r0[j])%PARAM_Q;
        }
    }

    /*
     * for the signer pi
     */

    /* pick a c_\pi and rebuild B_\pi */
    randombytes(seed, SEEDLEN);
    pol_unidrnd_with_seed(data[NOU-1].c, DIM, PARAM_Q, seed, SEEDLEN);

    /* compute  hash(c1,..., ck, m) */
    form_digest( msg, msg_len, data, hashdig);

    /* use u to temporarily store hash(c1,..., ck, m)*/
    for (i=0;i<64;i++)
    {
        tmpchar = hashdig[i];
        for (j=0;j<8;j++)
        {
            u[i*8+j] = tmpchar&1;
            tmpchar >>=1 ;
        }
    }

    /* compute d_\pi = u \xor d_i */
    for(i=0;i<DIM;i++)
    {
        for (j=0;j<NOU-1;j++)
        {
            u[i]+= data[j].d[i];
        }
    }
    for(i=0;i<DIM;i++)
    {
        data[NOU-1].d[i] = u[i]&1;
    }

    /* compute u = c_\pi - d_\pi*H*/
    ring_mul(u, data[NOU-1].d, H, DIM);
    for(i=0;i<DIM;i++)
    {
        u[i] = (data[NOU-1].c[i] - u[i])%PARAM_Q;
    }

    /* sign on u to get r0_\pi and r1_\pi*/
    unsigned char   nonce[PARAM_NONCE];
    falcon_sign     *fs;
    fs = falcon_sign_new();
    if (fs == NULL)
    {
        return -1;
    }
    randombytes(seed, SEEDLEN);
    falcon_sign_set_seed(fs, seed, SEEDLEN, 1);


    if (!falcon_sign_set_private_key(fs, sk, CRYPTO_SECRETKEYBYTES))
    {
        return -1;
    }
    if (!falcon_sign_start(fs, nonce))
    {
        return -1;
    }


    if(falcon_sign_with_u(fs, u, data[NOU-1].r0, data[NOU-1].r1)!=0)
    {
        printf("falcon sign failed\n");
        return -1;
    }


    falcon_sign_free(fs);
    free (tmp1);
    free (tmp2);
    free (u);
    free (hashdig);
    free (seed);

/*
 *  printf("horrey, signature is done!\n");
 */

    return 0;
}

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
raptor_keygen(
    raptor_data     data,
    unsigned char   *sk)
{
    /* Generate the public/private keypair */
    unsigned char       falcon_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char       falcon_sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    if ( (ret_val = crypto_sign_keypair(falcon_pk, falcon_sk)) != 0) {
        printf("crypto_sign_keypair returned <%d>\n", ret_val);
        return -1;
    }
    /* convert and store the keys */
    extract_pkey(falcon_pk, data.h);
    memcpy(sk, falcon_sk, CRYPTO_SECRETKEYBYTES);

/*
 *  printf("horrey, key gen is done!\n");
 */

    return 0;
}


int
raptor_fake_keygen(
    raptor_data     data)
{
    /*
     * generate a fake h to simulate a valid public key
     * in real world, should use a real public key
     */

    unsigned char *seed;
    seed    = malloc(SEEDLEN);
    if(!seed)
    {
        printf("memory error\n");
        return -1;
    }

    randombytes(seed, SEEDLEN);
    pol_unidrnd_with_seed(data.h, DIM, PARAM_Q, seed, SEEDLEN);

    free(seed);

    return 0;
}


void form_digest(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data        *data,
    unsigned char       *out)
{

    int             i;
    unsigned char   *hashbuf;
    int64_t         *ptr1, *ptr2;
    hashbuf = malloc(sizeof(int64_t)*DIM*NOU+msg_len);
    memcpy(hashbuf, msg, msg_len);
    ptr1 = (int64_t*)(hashbuf+msg_len);
    for (i=0;i<NOU;i++)
    {
        ptr2 = data[i].c;
        memcpy(ptr1+i*DIM,ptr2, sizeof(int64_t)*DIM);
    }
    crypto_hash_sha512(out, hashbuf, sizeof(int64_t)*NOU*DIM + msg_len);

    free(hashbuf);
    return;
}

int
raptor_verify(
    const unsigned char *msg,
    unsigned long long  msg_len,
    raptor_data         *data,
    int64_t             *H)
{
    int i,j;

    int64_t         *tmp1, *tmp2, *d, *drec;

    char            tmpchar;
    unsigned char   *hashdig;
    tmp1    = malloc(sizeof(int64_t)*DIM);
    tmp2    = malloc(sizeof(int64_t)*DIM);
    hashdig = malloc(64);

    d       = tmp1;
    drec    = tmp2;

    /* first, check if c = Bd+ (r0,r1)*(1,h)^T */
    for (i=0;i<NOU;i++)
    {
        ring_mul(tmp1, data[i].d, H, DIM);
        ring_mul(tmp2, data[i].r1, data[i].h, DIM);
        for (j=0;j<DIM;j++)
        {

            tmp1[j] = (tmp1[j] + tmp2[j] + data[i].r0[j] - data[i].c[j])%PARAM_Q;
            if (tmp1[j]!=0)
            {
                printf("error\n");
                return -1;
            }
        }
    }



    /* now check if hash (c1,...ck, m) = \xor di */
    memset(d, 0, sizeof(int64_t)*DIM);
    memset(drec, 0, sizeof(int64_t)*DIM);
    form_digest(msg, msg_len, data, hashdig);

    /* use u to temporarily store hash(c1,..., ck, m)*/
    for (i=0;i<64;i++)
    {
        tmpchar = hashdig[i];
        for (j=0;j<8;j++)
        {
            d[i*8+j] = tmpchar&1;
            tmpchar >>=1 ;
        }
    }

    for (i=0;i<NOU;i++)
    {
        for (j=0;j<DIM;j++)
        {
            drec[j] = drec[j] +  data[i].d[j];
        }
    }

    for (j=0;j<DIM;j++)
    {
        if ((drec[j]&1)!=d[j])
        {
            printf("error\n");
            return -1;
        }
    }


    free(tmp1);
    free(tmp2);
    free(hashdig);
/*
 *  printf("horrey, verification is done!\n");
 */
    return 0;
}

void
extract_skey(
    unsigned char       *falcon_sk,
    int64_t             *f,
    int64_t             *g,
    int64_t             *F,
    int64_t             *G)
{

    int                 i;
    unsigned char       *tmp;

    tmp = falcon_sk+1;

    for (i=0;i<DIM;i++)
    {

        if (tmp[i*2]>128)
            f[i] = tmp[i*2+1]-256;
        else
            f[i] = tmp[i*2+1];
    }
    for (i=0;i<DIM;i++)
    {
        if (tmp[DIM*2+i*2]>128)
            g[i] = tmp[DIM*2+i*2+1]-256;
        else
            g[i] = tmp[DIM*2+i*2+1];
    }
    for (i=0;i<DIM;i++)
    {
        if (tmp[DIM*4+i*2]>128)
            F[i] = tmp[DIM*4+i*2+1]-256;
        else
            F[i] = tmp[DIM*4+i*2+1];
    }
    for (i=0;i<DIM;i++)
    {
        if (tmp[DIM*6+i*2]>128)
            G[i] = tmp[DIM*6+i*2+1]-256;
        else
            G[i] = tmp[DIM*6+i*2+1];
    }

#ifdef DEBUG
    printf("f_res = vector([\n");
    for (i=0;i<DIM;i++)
    printf("%d, ",f[i]);
    printf("])\n");
    printf("g_res = vector([\n");
    for (i=0;i<DIM;i++)
    printf("%d, ",g[i]);
    printf("])\n");
    printf("F_res = vector([\n");
    for (i=0;i<DIM;i++)
    printf("%d, ",F[i]);
    printf("])\n");
    printf("G_res = vector([\n");
    for (i=0;i<DIM;i++)
    printf("%d, ",G[i]);
    printf("])\n");
#endif

    return;
}

void
extract_pkey(
    unsigned char       *falcon_pk,
    int64_t             *h)
{
    int                 i;
    uint16_t            *h16;


    h16 = malloc(sizeof(uint16_t)*DIM);
    falcon_decode_12289(h16, 9,falcon_pk+1, CRYPTO_PUBLICKEYBYTES-1);
    for (i=0;i<DIM;i++)
        h[i] = (int64_t) h16[i];
    free (h16);

#ifdef DEBUG
    printf("h = vector([\n");
    for (i=0;i<DIM;i++)
    printf("%d, ",h[i]);
    printf("])\n");
#endif
    return ;
}

