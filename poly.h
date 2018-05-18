/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * poly.h
 *
 *  Created on: May 11, 2018
 *      Author: zhenfei
 */

#ifndef POLY_H_
#define POLY_H_


void
karatsuba(
    int64_t        *res,       /* out - a * b in Z[x], must be length 2k */
    int64_t        *tmp,       /*  in - k coefficients of scratch space */
    int64_t const  *a,         /*  in - polynomial */
    int64_t const  *b,         /*  in - polynomial */
    uint16_t const  k);        /*  in - number of coefficients in a and b */

void
ring_mul(
    int64_t        *res,        /* out - a * b in Z[x], must be length 2k */
    int64_t const  *a,          /*  in - polynomial */
    int64_t const  *b,          /*  in - polynomial */
    uint16_t const  k) ;        /*  in - number of coefficients in a and b */

/* generate a random binary polynomial */
void binary_poly_gen(
    int64_t         *ai,
    const uint16_t  N);

/*
 * Discrete Gaussian sampler using Box-Muller method
 * with 53 bits of precision
 */

void DGS (
    int64_t         *v,         /* output   vector */
    const uint16_t  dim,        /* input    dimension */
    const uint8_t   stdev);     /* input    standard deviation */

void
pol_unidrnd_with_seed(
    int64_t         *v,
    const int16_t    N,
    const int16_t    q,
    unsigned char    *seed,
    const int16_t    seed_len);

#endif /* POLY_H_ */
