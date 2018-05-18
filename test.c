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

int main()
{


    int     i;

    raptor_data     data[NOU];
    unsigned char   *sk;

    int             mlen = 16;
    unsigned char   m[]  = "raptor: lattice based one time linkable ring signature";

    /* initializing pk */
    for (i=0;i<NOU;i++)
    {
        data[i].B     =   malloc(sizeof(int64_t)*DIM);
        data[i].c     =   malloc(sizeof(int64_t)*DIM);
        data[i].d     =   malloc(sizeof(int64_t)*DIM);
        data[i].r0    =   malloc(sizeof(int64_t)*DIM);
        data[i].r1    =   malloc(sizeof(int64_t)*DIM);
        data[i].h     =   malloc(sizeof(int64_t)*DIM);
        data[i].seedB =   malloc(SEEDLEN);
    }
    /* initializing sk */
    sk                =   malloc(CRYPTO_SECRETKEYBYTES);


    /* generating raptor keys */
    for  (i=0;i<NOU-1;i++)
    {
        raptor_fake_keygen(data[i]);
    }

    raptor_keygen(data[NOU-1], sk);

#ifdef DEBUG
    print_raptor_data(data[NOU-1]);
#endif


    /* performing signing */
    raptor_sign(m, mlen, data, sk);



    /* printing public data */
    for(i=0;i<NOU;i++)
        print_raptor_data(data[i]);


    raptor_verify (m, mlen, data);

    printf("we like raptor\n");
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
        a[i] = r%12289;
        rng_uint16(&r);
        b[i] = r%12289;
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
        printf("%lld, ",(long long)(res[i]%12289));
    printf("\n");

    return 0;
}
