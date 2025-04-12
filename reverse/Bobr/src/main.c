#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void functions() {
    asm("pop %rax ; ret");
    asm("pop %rdi ; ret");
    asm("pop %rsi ; ret");
    asm("pop %rdx ; ret");
    asm("pop %rcx ; ret");
    asm("pop %r8 ; ret");
    asm("pop %r9 ; ret");
    asm("pop %r15 ;ret");
    asm("movq %rax,(%rdi) ; ret");
    asm("xor %rax,(%rdi); ret");
    asm("xor %rax,(%r15) ; ret");
    asm("syscall ; ret");
    asm("pop %r10; ret");
    asm("movq (%rdi), %rax; ret");
    asm("bswap %rax; ret");
    asm("rol %cl, %rax ; ret");
    asm("ror %cl, %rax ; ret");
    asm("add %rcx, %rax ; ret");
    asm("sub %rcx, %rax ; ret");
    asm("movq (%r15), %rdi; ret");
    asm("movq (%r15), %rsi; ret");
    asm("movq (%r15), %rdx; ret");
    asm("movq (%r15), %rcx; ret");
}

void xor_data(unsigned char* data, const unsigned char* key, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key[i];
    }
}

void finish(uint64_t s1, uint64_t s2, uint64_t s3, uint64_t s4) {
    const unsigned char key[32] = {
            0x0a, 0x0a, 0x41, 0x15, 0x0b, 0x42, 0x49, 0x17,
            0x14, 0x43, 0x1c, 0x13, 0x02, 0x59, 0x02, 0x45,
            0x0a, 0x1d, 0x17, 0x1d, 0x49, 0x1d, 0x15, 0x02,
            0x10, 0x45, 0x4f, 0x16, 0x0b, 0x0c, 0x1a, 0x50
    };

    unsigned char data[32];
    memcpy(data, &s1, 8);
    memcpy(data + 8, &s2, 8);
    memcpy(data + 16, &s3, 8);
    memcpy(data + 24, &s4, 8);

    xor_data(data, key, 32);

    if (strstr((char*)data, "Ya obnimu tvoyo pushistoye tyelo") != NULL) {
        printf("You are welcome, bobr!\n");
    } else {
        printf("You are not a bobr, imposter!\n");
    }

    exit(0);
}

int main() {
    size_t pop_rax = (long) functions + 8;
    size_t pop_rdi = (long) functions + 8 + 2;
    size_t pop_rsi = (long) functions + 8 + 4;
    size_t pop_rdx = (long) functions + 8 + 6;
    size_t pop_rcx = (long) functions + 8 + 8;
    size_t pop_r8 = (long) functions + 8 + 10;
    size_t pop_r9 = (long) functions + 8 + 13;
    size_t pop_r15 = (long) functions + 8 + 16;
    size_t mov_rdi_rax = (long) functions + 8 + 19;
    size_t xor_qrdi_rax = (long) functions + 8 + 23;
    size_t xor_qr15_rax = (long) functions + 8 + 27;
    size_t syscall = (long) functions + 8 + 31;
    size_t pop_r10 = (long) functions + 8 + 34;
    size_t mov_rax_rdi = (long) functions + 8 + 37;
    size_t bswap_rax = (long) functions + 8 + 41;
    size_t rol_rax_cl = (long) functions + 8 + 45;
    size_t ror_rax_cl = (long) functions + 8 + 49;
    size_t add_rax_rcx = (long) functions + 8 + 53;
    size_t sub_rax_rcx = (long) functions + 8 + 57;
    size_t mov_rdi_r15 = (long) functions + 8 + 61;
    size_t mov_rsi_r15 = (long) functions + 8 + 65;
    size_t mov_rdx_r15 = (long) functions + 8 + 69;
    size_t mov_rcx_r15 = (long) functions + 8 + 73;
    int i = 0;
    size_t buf[5000] = {0x500000};

    // mmap
    buf[i++] = pop_rax;
    buf[i++] = 0x9;
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000;
    buf[i++] = pop_rsi;
    buf[i++] = 0x4000;
    buf[i++] = pop_rdx;
    buf[i++] = 0x7;
    buf[i++] = pop_r10;
    buf[i++] = 32 | 2;
    buf[i++] = pop_r8;
    buf[i++] = -1;
    buf[i++] = pop_r9;
    buf[i++] = 0;
    buf[i++] = syscall;

    // 1 part of input message
    buf[i++] = pop_r15;
    buf[i++] = 0x1001000;
    buf[i++] = pop_rax;
    buf[i++] = 0x72626f42202c6948;
    buf[i++] = xor_qr15_rax;

    // 2 part of input message
    buf[i++] = pop_r15;
    buf[i++] = 0x1001008;
    buf[i++] = pop_rax;
    buf[i++] = 0x207265746e452021;
    buf[i++] = xor_qr15_rax;

    // 3 part of input message
    buf[i++] = pop_r15;
    buf[i++] = 0x1001010;
    buf[i++] = pop_rax;
    buf[i++] = 0x7361702072756f79;
    buf[i++] = xor_qr15_rax;

    // 4 part of input message
    buf[i++] = pop_r15;
    buf[i++] = 0x1001018;
    buf[i++] = pop_rax;
    buf[i++] = 0x0a203a64726f7773;
    buf[i++] = xor_qr15_rax;

    // write input message
    buf[i++] = pop_rax;
    buf[i++] = 1;
    buf[i++] = pop_rdi;
    buf[i++] = 1;
    buf[i++] = pop_rsi;
    buf[i++] = 0x1001000;
    buf[i++] = pop_rdx;
    buf[i++] = 32;
    buf[i++] = syscall;

    // read input
    buf[i++] = pop_rax;
    buf[i++] = 0;
    buf[i++] = pop_rdi;
    buf[i++] = 0;
    buf[i++] = pop_rsi;
    buf[i++] = 0x1000000;
    buf[i++] = pop_rdx;
    buf[i++] = 34;
    buf[i++] = syscall;

    // First proccess 0-7 bits of input in rax (bswap, rol, sub)
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = pop_rcx;
    buf[i++] = 8;
    buf[i++] = rol_rax_cl;
    buf[i++] = pop_rcx;
    buf[i++] = 0x15f601f9fd5ad90c;
    buf[i++] = sub_rax_rcx;
    buf[i++] = mov_rdi_rax;

    // First proccess 8-15 bits of input in rax (bswap, rol, add)
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 8;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = pop_rcx;
    buf[i++] = 16;
    buf[i++] = rol_rax_cl;
    buf[i++] = pop_rcx;
    buf[i++] = 0x31fb05f9c12b3416;
    buf[i++] = add_rax_rcx;
    buf[i++] = mov_rdi_rax;

    // First proccess 16-23 bits of input in rax (bswap, rol, sub)
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 16;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = pop_rcx;
    buf[i++] = 8;
    buf[i++] = ror_rax_cl;
    buf[i++] = pop_rcx;
    buf[i++] = 0x73412ae3df40def;
    buf[i++] = add_rax_rcx;
    buf[i++] = mov_rdi_rax;

    // First proccess 24-31 bits of input in rax (bswap, rol, sub)
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 24;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = pop_rcx;
    buf[i++] = 16;
    buf[i++] = ror_rax_cl;
    buf[i++] = pop_rcx;
    buf[i++] = 0x4d0cf2e3ffc6fdcf;
    buf[i++] = sub_rax_rcx;
    buf[i++] = mov_rdi_rax;

    // Open bobr.bin
    buf[i++] = pop_rax;
    buf[i++] = 2;  // SYS_open
    buf[i++] = pop_rdi;
    buf[i++] = (size_t) "bobr.bin";
    buf[i++] = pop_rsi;
    buf[i++] = O_RDONLY;
    buf[i++] = syscall;

    // Read from bobr.bin
    buf[i++] = pop_rdi;
    buf[i++] = 3;
    buf[i++] = pop_rsi;
    buf[i++] = 0x1002000;
    buf[i++] = pop_rdx;
    buf[i++] = 32;
    buf[i++] = pop_rax;
    buf[i++] = 0;
    buf[i++] = syscall;

    // Close bobr.bin
    buf[i++] = pop_rdi;
    buf[i++] = 3;
    buf[i++] = pop_rax;
    buf[i++] = 3;
    buf[i++] = syscall;

    // xor 0-7 bytes
    buf[i++] = pop_r15;
    buf[i++] = 0x1002000;
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000;
    buf[i++] = mov_rax_rdi;
    buf[i++] = xor_qr15_rax;

    // xor 8-15 bytes
    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 8;
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 8;
    buf[i++] = mov_rax_rdi;
    buf[i++] = xor_qr15_rax;

    // xor 16-23 bytes
    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 16;
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 16;
    buf[i++] = mov_rax_rdi;
    buf[i++] = xor_qr15_rax;

    // xor 24-31 bytes
    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 24;
    buf[i++] = pop_rdi;
    buf[i++] = 0x1000000 + 24;
    buf[i++] = mov_rax_rdi;
    buf[i++] = xor_qr15_rax;

    // bswaps
    buf[i++] = pop_rdi;
    buf[i++] = 0x1002000;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = mov_rdi_rax;

    buf[i++] = pop_rdi;
    buf[i++] = 0x1002000 + 8;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = mov_rdi_rax;

    buf[i++] = pop_rdi;
    buf[i++] = 0x1002000 + 16;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = mov_rdi_rax;

    buf[i++] = pop_rdi;
    buf[i++] = 0x1002000 + 24;
    buf[i++] = mov_rax_rdi;
    buf[i++] = bswap_rax;
    buf[i++] = mov_rdi_rax;

    // Call finish()
    buf[i++] = pop_r15;
    buf[i++] = 0x1002000;
    buf[i++] = mov_rdi_r15;

    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 8;
    buf[i++] = mov_rsi_r15;

    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 16;
    buf[i++] = mov_rdx_r15;

    buf[i++] = pop_r15;
    buf[i++] = 0x1002000 + 24;
    buf[i++] = mov_rcx_r15;

    buf[i++] = (size_t) finish;

    // Start rop
    asm("mov %0, %%rsp" : : "r"(buf));
    asm("ret");
}