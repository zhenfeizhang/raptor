/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * print.c
 *
 *  Created on: May 15, 2018
 *      Author: zhenfei
 */

#include "raptor.h"


void print_raptor_data(
    raptor_data        data)
{
    int j;
    printf("\nprinting raptor data for (yet another) user \n");
    printf("c:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)data.c[j]);
    printf("\n");

    printf("r0:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)data.r0[j]);
    printf("\n");

    printf("r1:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)data.r1[j]);
    printf("\n");

    printf("d:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)data.d[j]);
    printf("\n");

    printf("h:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)data.h[j]);
    printf("\n");

    printf("\n==============================\n\n");
}



void print_raptor_sk(
    raptor_sk      sk)
{
    int j;

    printf("f:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)sk.f[j]);
    printf("\n");

    printf("g:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)sk.g[j]);
    printf("\n");

    printf("F:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)sk.F[j]);
    printf("\n");

    printf("G:\n");
    for (j=0;j<DIM;j++)
        printf("%lld, ",(long long)sk.G[j]);
    printf("\n");
}
