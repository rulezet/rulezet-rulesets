rule libavcodec_imc_weights1__flt64___64_big_248_ {
  strings:
    $a0 = { 3f be 9d c7 25 c3 de e8 3f bf 85 0d f1 5a 4a cf 3f c0 89 5d 0b 73 d1 89 3f b9 88 68 ef ad a2 65 3f b4 f8 e7 dd ca 4b 12 3f b8 9b 03 26 25 2d b7 3f b6 79 4e a0 77 03 6d 3f b6 0b ca 38 9d d6 3f 3f b7 10 05 30 c1 68 eb 3f b9 62 ee 0b e1 b5 92 3f bc ec fa 69 be 09 bb 3f c0 c8 bc 9c d3 e0 bd 3f c3 91 c4 b9 02 14 ad 3f c6 b1 81 16 eb d4 d0 3f cc 63 5a 42 6b b5 5b 3f cf 59 70 b4 9e 01 de 3f d1 1c da 2b 5a 20 de 3f d3 a2 df 93 78 ee 28 3f d4 ac c9 21 46 a1 a5 3f d5 96 28 cb d1 24 4a 3f d7 79 35 76 03 92 5c 3f d9 1f a7 65 34 37 3f 3f d9 7a 13 c2 54 a3 c6 3f d9 cf b3 31 1a 54 3f 3f db 2b 2b fd b4 cc 25 3f dc 77 39 f3 40 d4 dc 3f dc bf 7f 06 70 5c 89 3f dd 26 02 c9 08 1c 2e 3f de 95 24 bf d2 e9 47 3f e0 05 7a fe a3 df 6e 3f e0 55 27 e5 21 57 69 }

  condition:
    $a0
}