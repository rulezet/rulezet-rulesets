rule libavcodec_imc_weights1__flt64___64_lil_248_ {
  strings:
    $a0 = { e8 de c3 25 c7 9d be 3f cf 4a 5a f1 0d 85 bf 3f 89 d1 73 0b 5d 89 c0 3f 65 a2 ad ef 68 88 b9 3f 12 4b ca dd e7 f8 b4 3f b7 2d 25 26 03 9b b8 3f 6d 03 77 a0 4e 79 b6 3f 3f d6 9d 38 ca 0b b6 3f eb 68 c1 30 05 10 b7 3f 92 b5 e1 0b ee 62 b9 3f bb 09 be 69 fa ec bc 3f bd e0 d3 9c bc c8 c0 3f ad 14 02 b9 c4 91 c3 3f d0 d4 eb 16 81 b1 c6 3f 5b b5 6b 42 5a 63 cc 3f de 01 9e b4 70 59 cf 3f de 20 5a 2b da 1c d1 3f 28 ee 78 93 df a2 d3 3f a5 a1 46 21 c9 ac d4 3f 4a 24 d1 cb 28 96 d5 3f 5c 92 03 76 35 79 d7 3f 3f 37 34 65 a7 1f d9 3f c6 a3 54 c2 13 7a d9 3f 3f 54 1a 31 b3 cf d9 3f 25 cc b4 fd 2b 2b db 3f dc d4 40 f3 39 77 dc 3f 89 5c 70 06 7f bf dc 3f 2e 1c 08 c9 02 26 dd 3f 47 e9 d2 bf 24 95 de 3f 6e df a3 fe 7a 05 e0 3f 69 57 21 e5 27 55 e0 3f }

  condition:
    $a0
}