/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * test.c
 *
 *  Created on: May 14, 2018
 *      Author: zhenfei
 */


#include "raptor.h"
#include <time.h>

int test_linkable_raptor()
{

    int             i, j;
    clock_t         start, end;
    float           time_keygen, time_sign, time_verify;
    raptor_data     data[NOU];
    unsigned char   *sk;
    unsigned char   *seedH;
    int64_t         *H;
    int             ret_val;
    unsigned long   smlen;
    unsigned char   *ots_sk, *ots_pk, *ots_sm;

    int             mlen = 16;
    unsigned char   m[]  = "Raptor: next generation of Falcon with stealth mode";


    /* initializing public param */
    seedH           =   malloc(SEEDLEN);
    H               =   malloc(sizeof(int64_t)*DIM);
    randombytes(seedH,SEEDLEN);
    pol_unidrnd_with_seed(H, DIM, PARAM_Q, seedH, SEEDLEN);

    /* initializing pk */
    for (i=0;i<NOU;i++)
    {
        data[i].c   =   malloc(sizeof(int64_t)*DIM);
        data[i].d   =   malloc(sizeof(int64_t)*DIM);
        data[i].r0  =   malloc(sizeof(int64_t)*DIM);
        data[i].r1  =   malloc(sizeof(int64_t)*DIM);
        data[i].h   =   malloc(sizeof(int64_t)*DIM);
    }

    /* initializing sk */
    sk              =   malloc(CRYPTO_SECRETKEYBYTES);

    /* initializing falcon-based ots */
    int buflen  =   sizeof(int64_t)*DIM*NOU     /* b_i */
                +   sizeof(int64_t)*DIM*NOU*2   /* r_i */
                +   sizeof(int64_t)*DIM*NOU     /* h_i */
                +   CRYPTO_PUBLICKEYBYTES;      /* ots pk */

    ots_sk          =   malloc(CRYPTO_SECRETKEYBYTES);
    ots_pk          =   malloc(CRYPTO_PUBLICKEYBYTES);
    ots_sm          =   malloc(CRYPTO_BYTES + buflen);


    time_keygen =   0;
    time_sign   =   0;
    time_verify =   0;

    for  (i=0;i<NOU-1;i++)
    {
        raptor_fake_keygen(data[i]);
    }

    for (j=0;j<100;j++)
    {
        /* generating raptor keys */
        start = clock();

        raptor_keygen(data[NOU-1], sk);

#ifdef DEBUG
        print_raptor_data(data[NOU-1]);
#endif

        /* generating ots keys */
        if ( (ret_val = crypto_sign_keypair(ots_pk, ots_sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return -1;
        }
        end = clock();

//        linkable_raptor_keygen(data[NOU-1],sk, ots_pk, ots_sk);

        time_keygen += (float)(end-start);

        /* performing signing */

        start = clock();
        smlen = linkable_raptor_sign(m, mlen, data, sk, H, ots_pk, ots_sk, ots_sm);
        end = clock();
        time_sign += (float)(end-start);

        /* verify the signature */
        start = clock();
        linkable_raptor_verify (m, mlen, data, H, ots_pk, ots_sm, smlen);
        end = clock();
        time_verify += (float)(end-start);
    }


    /* printing public data */
    for(i=0;i<NOU;i++)
        print_raptor_data(data[i]);

    printf("time keygen :%f\n", time_keygen/100);
    printf("time sign :%f\n", time_sign/100);
    printf("time verify :%f\n", time_verify/100);



    free(H);
    free(seedH);
    free(sk);
    for (i=0;i<NOU;i++)
    {
        free(data[i].c);
        free(data[i].d);
        free(data[i].r0);
        free(data[i].r1);
        free(data[i].h);
    }

    printf("Linkable Raptor: next generation of Falcon with stealth mode\n");

    return 0;
}


int test_raptor()
{


    int             i, j;
    clock_t         start, end;
    float           time_keygen, time_sign, time_verify;
    raptor_data     data[NOU];
    unsigned char   *sk;
    unsigned char   *seedH;
    int64_t         *H;

    int             mlen = 16;
    unsigned char   m[]  = "Raptor: next generation of Falcon with stealth mode";


    /* initializing public param */
    seedH           =   malloc(SEEDLEN);
    H               =   malloc(sizeof(int64_t)*DIM);
    randombytes(seedH,SEEDLEN);
    pol_unidrnd_with_seed(H, DIM, PARAM_Q, seedH, SEEDLEN);

    /* initializing pk */
    for (i=0;i<NOU;i++)
    {
        data[i].c   =   malloc(sizeof(int64_t)*DIM);
        data[i].d   =   malloc(sizeof(int64_t)*DIM);
        data[i].r0  =   malloc(sizeof(int64_t)*DIM);
        data[i].r1  =   malloc(sizeof(int64_t)*DIM);
        data[i].h   =   malloc(sizeof(int64_t)*DIM);
    }

    /* initializing sk */
    sk              =   malloc(CRYPTO_SECRETKEYBYTES);


    time_keygen =   0;
    time_sign   =   0;
    time_verify =   0;

    for  (i=0;i<NOU-1;i++)
    {
        raptor_fake_keygen(data[i]);
    }

    for (j=0;j<100;j++)
    {
        /* generating raptor keys */
        start = clock();

        raptor_keygen(data[NOU-1], sk);

#ifdef DEBUG
        print_raptor_data(data[NOU-1]);
#endif
        end = clock();
        time_keygen += (float)(end-start);


        /* performing signing */



        start = clock();
        raptor_sign(m, mlen, data, sk, H);
        end = clock();
        time_sign += (float)(end-start);

        /* verify the signature */
        start = clock();
        raptor_verify (m, mlen, data, H);
        end = clock();
        time_verify += (float)(end-start);
    }


    /* printing public data */
    for(i=0;i<NOU;i++)
        print_raptor_data(data[i]);

    printf("time keygen :%f\n", time_keygen/100);
    printf("time sign :%f\n", time_sign/100);
    printf("time verify :%f\n", time_verify/100);



    free(H);
    free(seedH);
    free(sk);
    for (i=0;i<NOU;i++)
    {
        free(data[i].c);
        free(data[i].d);
        free(data[i].r0);
        free(data[i].r1);
        free(data[i].h);
    }

    printf("Raptor: next generation of Falcon with stealth mode\n");

    return 0;
}



int test_ring_mul()
{
    int64_t  *a,*b,*res;
    uint16_t  r;
    int i;
    int n=512;
    a    = malloc (sizeof(int64_t)*n);
    b    = malloc (sizeof(int64_t)*n);
    res  = malloc (sizeof(int64_t)*n*2);


    for(i=0;i<n;i++)
    {
        rng_uint16(&r);
        a[i] = r%PARAM_Q;
        rng_uint16(&r);
        b[i] = r%PARAM_Q;
    }

    ring_mul (res,a,b,n);



    printf("a:\n");
    for (i=0;i<n;i++)
        printf("%lld, ",(long long)a[i]);
    printf("\n");


    printf("b:\n");
    for (i=0;i<n;i++)
        printf("%lld, ",(long long)b[i]);
    printf("\n");

    printf("res:\n");
    for (i=0;i<n;i++)
        printf("%lld, ",(long long)(res[i]%PARAM_Q));
    printf("\n");

    return 0;
}


int main()
{
    test_raptor();
    test_linkable_raptor();
}
