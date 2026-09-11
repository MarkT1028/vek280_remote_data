#include "xparameters.h"
#include "xil_cache.h"
#include "xil_printf.h"
#include "xstatus.h"
#include "xiltimer.h"
#include "xckks_ciphertext_mult.h"

#define CKKS_RING_DIM       8192U
#define TEST_TOWER_COUNT    4U
#define TEST_WORD_COUNT     (CKKS_RING_DIM * TEST_TOWER_COUNT)
#define POLL_LIMIT          100000000U
#define MAX_PRINTED_ERRORS  10U

/*
 * Memory ABI shared with the HLS kernel (AArch64 is little-endian):
 *
 *   input pair:  [127:64] c1, [63:0] c0
 *   output word: [255:192] zero, [191:128] d2,
 *                [127:64] d1, [63:0] d0
 *   RNS params:  [255:145] zero, [144:64] floor(2^128/q), [63:0] q
 *
 * The board only handles RNS ciphertext data and public moduli.  No secret
 * key, plaintext, decryption key, decoding, or decryption is present here.
 */
typedef struct {
    u64 c0;
    u64 c1;
} CkksCiphertextPair;

typedef struct {
    u64 d0;
    u64 d1;
    u64 d2;
    u64 reserved;
} CkksCiphertextTriple;

typedef struct {
    u64 q;
    u64 reciprocal_low;
    u64 reciprocal_high;
    u64 reserved;
} CkksRnsParameter;

/*
 * Global static buffers keep roughly 2 MiB out of the small stack.  A future
 * PC/OpenFHE transport layer can write real ciphertext residues into lhs/rhs
 * without changing this hardware-facing layout.
 */
static CkksCiphertextPair lhs_words[TEST_WORD_COUNT]
    __attribute__((aligned(64)));
static CkksCiphertextPair rhs_words[TEST_WORD_COUNT]
    __attribute__((aligned(64)));
static CkksCiphertextTriple out_words[TEST_WORD_COUNT]
    __attribute__((aligned(64)));
static CkksRnsParameter rns_params[TEST_TOWER_COUNT]
    __attribute__((aligned(64)));

static const u64 moduli[TEST_TOWER_COUNT] = {
    36028797018652673ULL,
    18014398510645249ULL,
    1152921504606846883ULL,
    281474976710683ULL
};

/* floor(2^128/q), split at bit 64. */
static const u64 reciprocal_low[TEST_TOWER_COUNT] = {
    0x00000012FFFC0000ULL,
    0xFFFFFEE3FFF0004EULL,
    0x0000000000005D00ULL,
    0xFFFFFFE500000000ULL
};

static const u64 reciprocal_high[TEST_TOWER_COUNT] = {
    0x0200ULL,
    0x03FFULL,
    0x0010ULL,
    0xFFFFULL
};

static u64 rng_state = 0x0516D1A6ULL;

static u64 next_random(void)
{
    u64 x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static u64 multiply_mod_reference(u64 lhs, u64 rhs, u64 q)
{
    const unsigned __int128 product =
        (unsigned __int128)lhs * (unsigned __int128)rhs;
    return (u64)(product % (unsigned __int128)q);
}

static u64 add_mod_reference(u64 lhs, u64 rhs, u64 q)
{
    u64 sum = lhs + rhs;
    if (sum >= q) {
        sum -= q;
    }
    return sum;
}

static void print_u64_hex(u64 value)
{
    xil_printf("%08x%08x",
               (u32)(value >> 32),
               (u32)(value & 0xFFFFFFFFULL));
}

static void prepare_test_vectors(void)
{
    u32 tower;
    u32 coefficient;

    for (tower = 0U; tower < TEST_TOWER_COUNT; ++tower) {
        const u64 q = moduli[tower];
        const u32 base = tower * CKKS_RING_DIM;

        rns_params[tower].q = q;
        rns_params[tower].reciprocal_low = reciprocal_low[tower];
        rns_params[tower].reciprocal_high = reciprocal_high[tower];
        rns_params[tower].reserved = 0U;

        for (coefficient = 0U; coefficient < CKKS_RING_DIM;
             ++coefficient) {
            const u32 index = base + coefficient;
            lhs_words[index].c0 = next_random() % q;
            lhs_words[index].c1 = next_random() % q;
            rhs_words[index].c0 = next_random() % q;
            rhs_words[index].c1 = next_random() % q;
            out_words[index].d0 = 0U;
            out_words[index].d1 = 0U;
            out_words[index].d2 = 0U;
            out_words[index].reserved = 0U;
        }

        /* Deterministic boundary cases in every RNS tower. */
        lhs_words[base].c0 = q - 1U;
        lhs_words[base].c1 = q - 1U;
        rhs_words[base].c0 = q - 1U;
        rhs_words[base].c1 = q - 1U;

        lhs_words[base + 1U].c0 = 1U;
        lhs_words[base + 1U].c1 = q - 1U;
        rhs_words[base + 1U].c0 = q - 1U;
        rhs_words[base + 1U].c1 = 1U;
    }
}

static u32 verify_results(u64 *checksum_out)
{
    u32 tower;
    u32 coefficient;
    u32 errors = 0U;
    u64 checksum = 0U;

    for (tower = 0U; tower < TEST_TOWER_COUNT; ++tower) {
        const u64 q = moduli[tower];
        const u32 base = tower * CKKS_RING_DIM;

        for (coefficient = 0U; coefficient < CKKS_RING_DIM;
             ++coefficient) {
            const u32 index = base + coefficient;
            const u64 a0 = lhs_words[index].c0;
            const u64 a1 = lhs_words[index].c1;
            const u64 b0 = rhs_words[index].c0;
            const u64 b1 = rhs_words[index].c1;
            const u64 expected_d0 = multiply_mod_reference(a0, b0, q);
            const u64 expected_d1 = add_mod_reference(
                multiply_mod_reference(a0, b1, q),
                multiply_mod_reference(a1, b0, q),
                q);
            const u64 expected_d2 = multiply_mod_reference(a1, b1, q);

            checksum ^= out_words[index].d0
                        + 0x9E3779B97F4A7C15ULL
                        + (checksum << 6)
                        + (checksum >> 2);
            checksum ^= out_words[index].d1
                        + 0x9E3779B97F4A7C15ULL
                        + (checksum << 6)
                        + (checksum >> 2);
            checksum ^= out_words[index].d2
                        + 0x9E3779B97F4A7C15ULL
                        + (checksum << 6)
                        + (checksum >> 2);

            if (out_words[index].d0 != expected_d0 ||
                out_words[index].d1 != expected_d1 ||
                out_words[index].d2 != expected_d2 ||
                out_words[index].reserved != 0U) {
                if (errors < MAX_PRINTED_ERRORS) {
                    xil_printf("Mismatch tower=%u coefficient=%u\r\n",
                               tower, coefficient);
                    xil_printf("  expected d0=0x");
                    print_u64_hex(expected_d0);
                    xil_printf(" d1=0x");
                    print_u64_hex(expected_d1);
                    xil_printf(" d2=0x");
                    print_u64_hex(expected_d2);
                    xil_printf("\r\n  actual   d0=0x");
                    print_u64_hex(out_words[index].d0);
                    xil_printf(" d1=0x");
                    print_u64_hex(out_words[index].d1);
                    xil_printf(" d2=0x");
                    print_u64_hex(out_words[index].d2);
                    xil_printf("\r\n");
                }
                ++errors;
            }
        }
    }

    *checksum_out = checksum;
    return errors;
}

int main(void)
{
    XCkks_ciphertext_mult ip;
    XTime start_time;
    XTime end_time;
    u64 elapsed_ticks;
    u64 checksum;
    u32 elapsed_us;
    u32 poll_count;
    u32 errors;
    u32 kernel_status;
    int status;

    xil_printf("\r\n");
    xil_printf("========================================================\r\n");
    xil_printf("VEK280 CKKS two-ciphertext multiplication self-test\r\n");
    xil_printf("No plaintext or secret key is present on the board\r\n");
    xil_printf("========================================================\r\n");

    if (sizeof(CkksCiphertextPair) != 16U ||
        sizeof(CkksCiphertextTriple) != 32U ||
        sizeof(CkksRnsParameter) != 32U) {
        xil_printf("FAIL: unexpected compiler structure layout\r\n");
        return XST_FAILURE;
    }

    status = XCkks_ciphertext_mult_Initialize(
        &ip,
        (UINTPTR)XPAR_XCKKS_CIPHERTEXT_MULT_0_BASEADDR);
    if (status != XST_SUCCESS) {
        xil_printf("FAIL: IP initialization returned %d\r\n", status);
        return XST_FAILURE;
    }

    xil_printf("IP control base: 0x%08x\r\n",
               (u32)XPAR_XCKKS_CIPHERTEXT_MULT_0_BASEADDR);
    xil_printf("Preparing %u towers x %u residues...\r\n",
               TEST_TOWER_COUNT, CKKS_RING_DIM);
    prepare_test_vectors();

    /*
     * CPU writes are initially in its data cache.  The HLS IP is an
     * independent AXI master, so publish every input and clear any dirty
     * output cache lines before starting the accelerator.
     */
    Xil_DCacheFlushRange((UINTPTR)lhs_words, (u32)sizeof(lhs_words));
    Xil_DCacheFlushRange((UINTPTR)rhs_words, (u32)sizeof(rhs_words));
    Xil_DCacheFlushRange((UINTPTR)out_words, (u32)sizeof(out_words));
    Xil_DCacheFlushRange((UINTPTR)rns_params, (u32)sizeof(rns_params));

    XCkks_ciphertext_mult_Set_lhs(&ip, (u64)(UINTPTR)lhs_words);
    XCkks_ciphertext_mult_Set_rhs(&ip, (u64)(UINTPTR)rhs_words);
    XCkks_ciphertext_mult_Set_out_r(&ip, (u64)(UINTPTR)out_words);
    XCkks_ciphertext_mult_Set_rns_params(
        &ip, (u64)(UINTPTR)rns_params);
    XCkks_ciphertext_mult_Set_ring_dim(&ip, CKKS_RING_DIM);
    XCkks_ciphertext_mult_Set_tower_count(&ip, TEST_TOWER_COUNT);

    xil_printf("Starting FPGA ciphertext kernel...\r\n");
    XTime_GetTime(&start_time);
    XCkks_ciphertext_mult_Start(&ip);

    poll_count = 0U;
    while (XCkks_ciphertext_mult_IsDone(&ip) == 0U) {
        ++poll_count;
        if (poll_count >= POLL_LIMIT) {
            xil_printf("FAIL: timeout waiting for HLS IP\r\n");
            return XST_FAILURE;
        }
    }
    XTime_GetTime(&end_time);

    kernel_status = XCkks_ciphertext_mult_Get_return(&ip);
    if (kernel_status != 0U) {
        xil_printf("FAIL: kernel returned status %u\r\n", kernel_status);
        return XST_FAILURE;
    }

    /* FPGA wrote LPDDR directly; discard stale CPU cache lines before read. */
    Xil_DCacheInvalidateRange(
        (UINTPTR)out_words, (u32)sizeof(out_words));

    elapsed_ticks = (u64)(end_time - start_time);
    elapsed_us = (u32)((elapsed_ticks * 1000000ULL) /
                       (u64)COUNTS_PER_SECOND);

    xil_printf("FPGA kernel completed\r\n");
    xil_printf("Timer ticks: %u\r\n", (u32)elapsed_ticks);
    xil_printf("Kernel time: %u us\r\n", elapsed_us);

    errors = verify_results(&checksum);
    if (errors != 0U) {
        xil_printf("FAIL: %u / %u ciphertext words mismatched\r\n",
                   errors, TEST_WORD_COUNT);
        return XST_FAILURE;
    }

    xil_printf("PASS: complete (c0,c1) x (c0,c1) multiply\r\n");
    xil_printf("Validated %u towers x %u residues\r\n",
               TEST_TOWER_COUNT, CKKS_RING_DIM);
    xil_printf("Output components: d0, d1, d2\r\n");
    xil_printf("checksum=0x");
    print_u64_hex(checksum);
    xil_printf("\r\n");

    return XST_SUCCESS;
}
