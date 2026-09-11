# VEK280 CKKS RNS remote deployment bundle

This directory contains the files needed to run the standalone
`ckks_ciphertext_mult` hardware self-test on a remote VEK280 board.

## Contents

- `deploy/system_wrapper_ckks_ciphertext_mult.pdi`: Versal device image.
- `deploy/ckks_ciphertext_mult_test.elf`: Cortex-A72 standalone test program.
- `hardware/system_wrapper_ckks_ciphertext_mult.xsa`: hardware handoff used to
  rebuild the Vitis platform.
- `source/main.c`: source for the standalone test program.
- `SHA256SUMS.txt`: SHA-256 integrity hashes for the four files above.

Only the two files under `deploy/` are required for a prebuilt JTAG run. The
XSA and C source are included so the application can be rebuilt with Vitis
2025.2 if necessary.

## Remote JTAG run

1. Connect the VEK280 to the remote host through its JTAG/UART USB connection
   and select JTAG boot mode.
2. Program the device with
   `deploy/system_wrapper_ckks_ciphertext_mult.pdi`.
3. Download `deploy/ckks_ciphertext_mult_test.elf` to
   `psv_cortexa72_0` and run it.
4. Monitor the PS UART at 115200 baud, 8 data bits, no parity, one stop bit.

The successful final output contains:

```text
PASS: complete (c0,c1) x (c0,c1) multiply
Validated 4 towers x 8192 residues
Output components: d0, d1, d2
checksum=0x...
```

This is a deterministic RNS datapath self-test. It does not contain a secret
key, plaintext, or decryption code, and it is not yet the full OpenFHE
ciphertext import/decrypt workflow.
