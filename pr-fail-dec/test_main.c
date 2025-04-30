//  test_main.c
//  === stub main

#include <stdio.h>
#include <stddef.h>

double mlkem_fp_summary(size_t eps);    //  mlkem_fp.c
double mmcipher_fp_summary(size_t eps); //  mmcipher_fp.c

int main()
{
    mlkem_fp_summary(256);
    mmcipher_fp_summary(256);

    return 0;
}
