#include <stdio.h>
#include <time.h>

//#define CLOCKS_PER_SEC 10

void sha256_init(void);
void __fastcall__ sha256_next_block_fastcall(unsigned char size, unsigned char *data);
void sha256_finalize(void);
extern unsigned char sha256_hash[32];
extern unsigned long buffer[64];

unsigned char data[64]= "123456789012345678901234567890123456789012345678901234567890123";
unsigned char ref[32] = {
    0x35,0x0d,0x1d,0x29,0x55,0x74,0xaf,0xe1,
    0xea,0x25,0x8b,0xbf,0x7b,0xc0,0xc6,0x93,
    0x19,0xfd,0x7c,0xab,0x37,0xa2,0x4d,0xc3,
    0x2a,0xa8,0x1a,0xa7,0x0f,0xab,0x9b,0x2e
};

int main()
{
#ifdef __C64__
    int t_total, secs, tens;
    int t_start;
#endif
    int i, blocks = 64;
    char ok = 1;
    unsigned char *SCROLY = (unsigned char *)53265U;
    data[63] = 0x0a;    // so that cc65 does not translate it to C64's newline.

    printf("\nSHA-256 for 6502 by Laubzega/WFMH'21\n\n");
    printf("Hashing %d blocks of 64 bytes", blocks);
#ifdef __C64__
    *SCROLY = 0;
    t_start = clock();
#endif
    sha256_init();
    for (i = 0; i < blocks; i++) {
        if ((i & 0x01f) == 0)
            printf(".");
        sha256_next_block_fastcall(64, data);
    }

    sha256_finalize();

    printf("\nNeeded: ");
    for (i = 0; i < 32; i++)
        printf("%02x", ref[i]);

    printf("\nHashed: ");
    for (i = 0; i < 32; i++)
        printf("%02x", sha256_hash[i]);


    for (i = 0; i < 32; i++)
        if (ref[i] != sha256_hash[i]) {
            ok = 0;
            break;
        }

#ifdef __C64__
    t_total = clock() - t_start;
#endif

    printf(ok ? "\nMATCH!\n" : "\nFAIL!?\n");

#ifdef __C64__
    *SCROLY = 27;
    secs = t_total / CLOCKS_PER_SEC;
    tens = 100 * (t_total - secs * CLOCKS_PER_SEC) / CLOCKS_PER_SEC;
    printf("\nTime: %d.%02d s (%ld bytes/s)\n", secs, tens, CLOCKS_PER_SEC * (64L * blocks) / t_total);
#endif
    return 0;
}
