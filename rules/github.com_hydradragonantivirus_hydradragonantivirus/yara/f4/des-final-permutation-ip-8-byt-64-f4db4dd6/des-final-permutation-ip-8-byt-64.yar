rule DES_final_permutation_IP__8_byt_64_ {
  strings:
    $a0 = { 28 08 30 10 38 18 40 20 27 07 2f 0f 37 17 3f 1f 26 06 2e 0e 36 16 3e 1e 25 05 2d 0d 35 15 3d 1d 24 04 2c 0c 34 14 3c 1c 23 03 2b 0b 33 13 3b 1b 22 02 2a 0a 32 12 3a 1a 21 01 29 09 31 11 39 02 }

  condition:
    $a0
}