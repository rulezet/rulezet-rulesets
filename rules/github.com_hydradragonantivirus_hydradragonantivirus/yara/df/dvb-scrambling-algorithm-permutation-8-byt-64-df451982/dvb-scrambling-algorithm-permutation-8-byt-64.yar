rule DVB_scrambling_algorithm_permutation__8_byt_64_ {
  strings:
    $a0 = { 11 23 08 06 29 30 1c 14 1b 35 3d 31 12 20 3a 3f 17 13 24 26 01 34 1a 00 21 03 0c 0d 38 27 19 28 32 22 33 0b 15 2f 1d 39 2c 1e 07 18 16 2e 3c 10 3b 04 37 2a 0a 05 09 2b 1f 3e 2d 0e 02 25 0f 36 }

  condition:
    $a0
}