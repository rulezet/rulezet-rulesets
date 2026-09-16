rule libavcodec_imc_quantizer1__flt32___32_lil_128_ {
  strings:
    $a0 = { d5 24 58 3f 79 79 f2 3e aa 63 b9 3f 4d 9e 8a 3e e6 96 3e 3f 90 f9 9e 3f d2 38 ec 3f 00 00 00 00 84 67 5e 3f 9b 03 f4 3e 72 36 bd 3f da 71 83 3e 9a 7a 41 3f 93 57 a9 3f 48 33 02 40 00 00 00 00 41 48 42 3f 1a 6b 1f 3f ae ba a2 3f 79 20 b2 3e 35 d0 40 3f 55 4c 93 3f e7 71 d0 3f 00 00 00 00 e2 e7 43 3f 96 07 25 3f fc c4 a1 3f e3 e2 b0 3e 9c 8b 43 3f 9f 73 9b 3f c9 c6 e1 3f 00 00 00 00 }

  condition:
    $a0
}