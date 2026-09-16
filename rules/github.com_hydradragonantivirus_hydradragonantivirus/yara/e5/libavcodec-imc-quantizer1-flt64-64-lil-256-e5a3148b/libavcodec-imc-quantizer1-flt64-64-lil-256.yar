rule libavcodec_imc_quantizer1__flt64___64_lil_256_ {
  strings:
    $a0 = { a5 3d d2 9e 9a 04 eb 3f 18 0a f9 1c 2f 4f de 3f 17 7e 70 3e 75 2c f7 3f 22 55 f3 a0 c9 53 d1 3f b3 89 61 c1 dc d2 e7 3f 46 d2 6e f4 31 df f3 3f 04 a9 14 3b 1a 87 fd 3f 00 00 00 00 00 00 00 00 c0 c9 57 7e f0 cc eb 3f 54 38 a3 62 73 80 de 3f cc 98 82 35 ce a6 f7 3f e2 23 41 3c 3b 6e d0 3f 2f 35 42 3f 53 2f e8 3f 4e 86 99 6c f2 2a f5 3f 83 17 7d 05 69 46 00 40 00 00 00 00 00 00 00 00 a8 97 8c 21 08 49 e8 3f 74 52 eb 3f 63 ed e3 3f 0a f7 ca bc 55 57 f4 3f 04 72 89 23 0f 44 d6 3f 80 ca 84 a1 06 1a e8 3f 78 0e 65 a8 8a 69 f2 3f 64 22 a5 d9 3c 0e fa 3f 00 00 00 00 00 00 00 00 4f 1f 81 3f fc 7c e8 3f 48 dd ce be f2 a0 e4 3f 02 66 be 83 9f 38 f4 3f fa b2 d5 61 5c 1c d6 3f ad 69 ff 7f 73 71 e8 3f b9 a9 81 e6 73 6e f3 3f d8 ab d9 14 d9 38 fc 3f 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}