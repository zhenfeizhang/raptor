/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * poly.c
 *
 *  Created on: May 11, 2018
 *      Author: zhenfei
 */

#include "raptor.h"

/* reduction mod x^n+1 ring */
void
ring_mul(
    int64_t        *res,        /* out - a * b in Z[x], must be length 2k */
    int64_t const  *a,          /*  in - polynomial */
    int64_t const  *b,          /*  in - polynomial */
    uint16_t const  k)          /*  in - number of coefficients in a and b */
{
    uint16_t i;

    int64_t *res1, *tmp;
    res1 = malloc (sizeof(int64_t)*k*3);
    if (!res1)
    {
        printf("malloc error\n");
        return;
    }
    tmp = res1 + 2*k;

    karatsuba(res1, tmp, a, b, k);
    for (i=0;i<k;i++)
    {
        res[i] = res1[i] - res1[i+k];
        res[i] %= PARAM_Q;
    }
    free(res1);

}
/* Space efficient Karatsuba multiplication.
 * See: Thomé, "Karatsuba multiplication with temporary space of size \le n"
 * http://www.loria.fr/~thome/files/kara.pdf
 *
 * Note: Input length should factor into b * 2^k, b <= 38
 */
void
karatsuba(
    int64_t        *res1,      /* out - a * b in Z[x], must be length 2k */
    int64_t        *tmp1,      /*  in - k coefficients of scratch space */
    int64_t const  *a,         /*  in - polynomial */
    int64_t const  *b,         /*  in - polynomial */
    uint16_t const  k)          /*  in - number of coefficients in a and b */
{
  uint16_t i;
  uint16_t j;

  /* Grade school multiplication for small / odd inputs */
  if(k <= 32 || (k & 1) != 0)
  {
    for(j=0; j<k; j++)
    {
      res1[j] = a[0]*b[j];
    }
    for(i=1; i<k; i++)
    {
      res1[i+k-1] = 0;
      for(j=0; j<k; j++)
      {
        res1[i+j] += a[i]*b[j];
      }
    }
    res1[2*k-1] = 0;

    return;
  }

  uint16_t const p = k>>1;

  int64_t *res2 = res1+p;
  int64_t *res3 = res1+k;
  int64_t *res4 = res1+k+p;
  int64_t *tmp2 = tmp1+p;
  int64_t const *a2 = a+p;
  int64_t const *b2 = b+p;

  for(i=0; i<p; i++)
  {
    res1[i] = a[i] - a2[i];
    res2[i] = b2[i] - b[i];
  }

  karatsuba(tmp1, res3, res1, res2, p);

  karatsuba(res3, res1, a2, b2, p);

  for(i=0; i<p; i++)
  {
    tmp1[i] += res3[i];
  }

  for(i=0; i<p; i++)
  {
    res2[i]  = tmp1[i];
    tmp2[i] += res4[i];
    res3[i] += tmp2[i];
  }

  karatsuba(tmp1, res1, a, b, p);

  for(i=0; i<p; i++)
  {
    res1[i]  = tmp1[i];
    res2[i] += tmp1[i] + tmp2[i];
    res3[i] += tmp2[i];
  }

  return;
}


/*
 * Discrete Gaussian sampler using Box-Muller method
 * with 53 bits of precision
 */

void DGS (      int64_t   *v,       /* output   vector */
          const uint16_t  dim,      /* input    dimension */
          const uint8_t   stdev)    /* input    standard deviation */
{
    uint16_t d2 = dim/2;
    uint16_t i;
    uint64_t t;

    static double const Pi=3.141592653589793238462643383279502884L;
    static long const bignum = 0xfffffff;
    double r1, r2, theta, rr;

    for (i=0;i<d2;i++)
    {
        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[2*i] = (int64_t) floor(rr*sin(theta) + 0.5);
        v[2*i+1] = (int64_t) floor(rr*cos(theta) + 0.5);
    }

    if (dim%2 == 1)
    {
        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[dim-1] = (int64_t) floor(rr*sin(theta) + 0.5);
    }
}



/* generate a random binary polynomial */
void binary_poly_gen(
        int64_t         *ai,
        const uint16_t  N)
{
    uint16_t r;
    uint64_t i,j,index;
    for (i=0;i<=N/16;i++)
    {
        rng_uint16(&r);
        for (j=0;j<16;j++)
        {
            index = i*16+j;
            if (index<N)
                ai[index] = (r & ( 1 << j)) >> j;
        }
    }
}

/* Uniform random element of pZ^n, v, such that
 * v_i + (p-1)/2 <= (q-1)/2
 * v_i - (p-1)/2 >= -(q-1)/2
 */
void
pol_unidrnd_with_seed(
    int64_t         *v,
    const int16_t    N,
    const int16_t    q,
    unsigned char    *seed,
    const int16_t    seed_len)
{
    int16_t   i = 0, j = 0;
    uint16_t  *buf;

    buf = malloc(sizeof(int64_t)*64);
    if (!buf)
    {
        printf("malloc error\n");
        return;
    }

#ifdef DEBUG
    printf("seed:\n");
    for (i=0;i<seed_len;i++)
        printf("%d, ", seed[i]);
    printf("\n");
    i=0;
#endif

    crypto_hash_sha512((unsigned char*)buf, seed, seed_len);


    while (i<N)
    {
        crypto_hash_sha512((unsigned char*)buf, (unsigned char*)buf, 64);
        for (j=0;j<32;j++)
        {
            if ((buf[j]<5*q) && (i<N))
            v[i++] = buf[j]%q;
        }
    }
    free(buf);

    return;
}


