rule libfaad2_pan_pow_2_neg__flt32___32_lil_160_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f e0 28 64 3f e0 28 64 3f d5 58 4b 3f d5 58 4b 3f d5 58 4b 3f d5 58 4b 3f d5 58 4b 3f 03 86 21 3f 26 f5 0f 3f 26 f5 0f 3f 97 3b 35 3f 03 86 21 3f 50 4d 00 3f 0e a9 b5 3e 93 e7 a1 3e 03 86 21 3f 50 4d 00 3f 0e a9 b5 3e d7 3c 65 3e 03 1a 36 3e 24 f5 0f 3f a9 d3 cb 3e d7 3c 65 3e c7 ea 00 3e 02 88 b6 3d 50 4d 00 3f 1a 4c 90 3e d5 a5 10 3e 2e fd 90 3d 8b 10 23 3d a9 d3 cb 3e 68 52 4c 3e 0f 88 b6 3d 8b 10 23 3d 9b ac 91 3c }

  condition:
    $a0
}