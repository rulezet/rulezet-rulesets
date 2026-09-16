rule libavcodec_imc_weights2__flt64___64_big_248_ {
  strings:
    $a0 = { 3f 6a 7f 92 dd 3c dc 7f 3f 6c a9 a4 28 be bb 11 3f 70 51 a9 c0 d9 23 9d 3f 60 3a cb 2d 0f 82 aa 3f 53 14 e5 6a 52 84 31 3f 5d 5f ac 8d e8 0a 96 3f 56 ff a0 df 89 12 0d 3f 55 d5 ea ad b3 57 05 3f 58 a9 64 67 de 8b 91 3f 5f f5 93 c0 66 b7 f0 3f 66 bb 02 74 fa 52 ed 3f 70 fc b4 f1 e4 b4 4a 3f 79 b6 8a 6b 28 6d 07 3f 83 2d 70 25 ac e2 cd 3f 91 8d 11 cb da 5e 86 3f 96 f1 63 85 0a 96 5c 3f 9d 14 21 1f 34 78 ae 3f a5 14 17 0e 39 7e a7 3f a8 39 de 48 1f 53 82 3f ab 38 31 9f b5 3c 8d 3f b1 10 b8 b4 e7 d3 b9 3f b4 80 47 b8 fc 35 70 3f b5 49 e5 26 5f e6 1a 3f b6 0d 40 5a 63 22 e5 3f b9 53 02 dc 53 52 8d 3f bc b8 f1 4d b5 95 79 3f bd 7f 84 44 9d be c2 3f be 9e f5 23 2d 2b b2 3f c1 6e 26 4e 48 62 6f 3f c3 c5 04 81 6f 00 69 3f c4 d2 dc b1 46 5e 89 }

  condition:
    $a0
}