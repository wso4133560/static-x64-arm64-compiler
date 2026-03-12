
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frvdec.h"

static int test_impl(FrvOptions opt, unsigned len, uint32_t inst_raw,
                     const char* exp_fmt) {
  FrvInst inst;
  char fmt[128];
  int retval = frv_decode(len, (unsigned char*) &inst_raw, opt, &inst);
  if (retval == FRV_PARTIAL)
    strcpy(fmt, "PARTIAL");
  else if (retval == FRV_UNDEF)
    strcpy(fmt, "UNDEF");
  else
    frv_format(&inst, sizeof fmt, fmt);
  if ((retval < 0 || (unsigned) retval == len) && !strcmp(fmt, exp_fmt))
    return 0;
  printf("Failed case: %08" PRIx32, inst_raw);
  printf("\n  Exp (%2zu): %s", sizeof inst_raw, exp_fmt);
  printf("\n  Got (%2d): %s\n", retval, fmt);
  return -1;
}

#define test32(...) test_impl(FRV_RV32, __VA_ARGS__)
#define test64(...) test_impl(FRV_RV64, __VA_ARGS__)
#define test(...) test32(__VA_ARGS__) | test64(__VA_ARGS__)

int main(void) {
  unsigned failed = 0;
  failed |= test(4, 0x00000000, "UNDEF");
  failed |= test(4, 0x00054703, "lbu r14 r10");
  failed |= test(4, 0xfe043783, "ld r15 r8 -32");
  failed |= test(4, 0xfe043023, "sd r8 r0 -32");
  failed |= test(4, 0x00d71463, "bne r14 r13 8");
  failed |= test(4, 0xfe0718e3, "bne r14 r0 -16");
  failed |= test(4, 0x0ff67613, "andi r12 r12 255");
  failed |= test64(4, 0x0007879b, "addiw r15 r15");
  failed |= test(4, 0x00008067, "jalr r0 r1");
  failed |= test(4, 0x0700006f, "jal r0 112");
  failed |= test(4, 0x20a93c27, "fsd r18 r10 536");
  failed |= test64(4, 0xe20505d3, "fmv.x.d r11 r10");
  failed |= test64(4, 0xd2287553, "fcvt.d.l r10 r16");
  failed |= test(4, 0x02957553, "fadd.d r10 r10 r9");
  failed |= test(4, 0x420686d3, "fcvt.d.s r13 r13");
  failed |= test(4, 0x00100013, "addi r0 r0 1");

  failed |= test(2, 0x4601, "addi r12 r0"); // implicit 0 in printed output
  failed |= test(2, 0x002c, "addi r11 r2 8");
  failed |= test(2, 0x714d, "addi r2 r2 -336");
  failed |= test(2, 0x0521, "addi r10 r10 8");
  failed |= test(2, 0x1571, "addi r10 r10 -4");
  failed |= test(2, 0x00a8, "addi r10 r2 72");
  failed |= test32(2, 0x641c, "flw r15 r8 8");
  failed |= test(2, 0x87b6, "add r15 r0 r13");
  failed |= test(2, 0xc05c, "sw r8 r15 4");
  failed |= test64(2, 0x6582, "ld r11 r2");
  failed |= test64(2, 0xfa22, "sd r2 r8 304");
  failed |= test64(2, 0xc93e, "sw r2 r15 144");
  failed |= test64(2, 0x47c2, "lw r15 r2 16");
  failed |= test32(2, 0xe09c, "fsw r9 r15");
  failed |= test64(2, 0xe09c, "sd r9 r15");
  failed |= test(2, 0x050e, "slli r10 r10 3");
  failed |= test(2, 0xfe75, "bne r12 r0 -4");
  failed |= test(2, 0xa029, "jal r0 10");
  failed |= test(2, 0x78fd, "lui r17 -4096");
  failed |= test(2, 0x0001, "addi r0 r0"); /* C.ADDI is normally not allowed an imm=0, except with rd=0 encoding a NOP */

  failed |= test(4, 0x0987073b, "add.uw r14 r14 r24");
  failed |= test(4, 0x411a7cb3, "andn r25 r20 r17");
  failed |= test(4, 0x49341333, "bclr r6 r8 r19");
  failed |= test(4, 0x48dc1313, "bclri r6 r24 13");
  failed |= test(4, 0x48a0dab3, "bext r21 r1 r10");
  failed |= test(4, 0x4b7b5793, "bexti r15 r22 55");
  failed |= test(4, 0x68c395b3, "binv r11 r7 r12");
  failed |= test(4, 0x6bb99813, "binvi r16 r19 59");
  failed |= test(4, 0x28341433, "bset r8 r8 r3");
  failed |= test(4, 0x28941693, "bseti r13 r8 9");
  failed |= test(4, 0x0a9a1833, "clmul r16 r20 r9");
  failed |= test(4, 0x0a1738b3, "clmulh r17 r14 r1");
  failed |= test(4, 0x0b382a33, "clmulr r20 r16 r19");
  failed |= test(4, 0x60011c13, "clz r24 r2");
  failed |= test(4, 0x6002131b, "clzw r6 r4");
  failed |= test(4, 0x602a9813, "cpop r16 r21");
  failed |= test(4, 0x602b969b, "cpopw r13 r23");
  failed |= test(4, 0x601a1513, "ctz r10 r20");
  failed |= test(4, 0x60191a1b, "ctzw r20 r18");
  failed |= test(4, 0x0a56e433, "max r8 r13 r5");
  failed |= test(4, 0x0b247a33, "maxu r20 r8 r18");
  failed |= test(4, 0x0b7445b3, "min r11 r8 r23");
  failed |= test(4, 0x0b825c33, "minu r24 r4 r24");
  failed |= test(4, 0x287cda93, "orc.b r21 r25");
  failed |= test(4, 0x405ae5b3, "orn r11 r21 r5");
  failed |= test(4, 0x6b8c5213, "rev8 r4 r24");
  failed |= test(4, 0x60dc99b3, "rol r19 r25 r13");
  failed |= test(4, 0x6018183b, "rolw r16 r16 r1");
  failed |= test(4, 0x60f65233, "ror r4 r12 r15");
  failed |= test(4, 0x60c25893, "rori r17 r4 12");
  failed |= test(4, 0x606a529b, "roriw r5 r20 6");
  failed |= test(4, 0x6053dcbb, "rorw r25 r7 r5");
  failed |= test(4, 0x604b9b93, "sext.b r23 r23");
  failed |= test(4, 0x605a9293, "sext.h r5 r21");
  failed |= test(4, 0x2057a633, "sh1add r12 r15 r5");
  failed |= test(4, 0x20d4a0bb, "sh1add.uw r1 r9 r13");
  failed |= test(4, 0x203a4933, "sh2add r18 r20 r3");
  failed |= test(4, 0x2101c2bb, "sh2add.uw r5 r3 r16");
  failed |= test(4, 0x2062e4b3, "sh3add r9 r5 r6");
  failed |= test(4, 0x2079e23b, "sh3add.uw r4 r19 r7");
  failed |= test(4, 0x0929121b, "slli.uw r4 r18 18");
  failed |= test(4, 0x403a40b3, "xnor r1 r20 r3");
  failed |= test(4, 0x0809483b, "zext.h r16 r18");

  puts(failed ? "Some tests FAILED" : "All tests PASSED");
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
