rule EPWIC_s_from_var_func__flt32___32_big_244_ {
  strings:
    $a0 = { be 9a 20 9b be 82 23 5b be 50 b6 b7 be 19 d1 2d bd bf 9c 48 bd 0b 7a d8 3c e6 8a 43 3d be 35 83 3e 23 da 73 3e 6a f1 02 3e 9a 20 9b 3e bf d8 8c 3e e6 94 68 3f 07 24 85 3f 1b 76 3e 3f 30 3a a8 3f 45 6d 6e 3f 5b 0a 81 3f 71 0e 45 3f 83 ba 88 3f 8f 1d e7 3f 9a af 79 3f a6 6e 44 3f b2 58 a3 3f be 6d 48 3f ca aa e3 3f d7 10 77 3f e3 9d 5e 3f f0 4f a0 3f fd 27 3d 40 05 11 49 40 0b a0 a5 40 12 41 0b 40 18 f2 28 40 1f b3 a7 40 26 85 34 40 2d 66 51 40 34 56 d6 40 3b 56 43 40 42 64 6f 40 49 81 06 40 50 ab b4 40 57 e4 26 40 5f 2a 30 40 66 7d aa 40 6d de 16 40 75 4b 73 40 7c c5 6d 40 82 25 d9 40 85 ef 20 40 89 be 62 40 8d 93 8a 40 91 6e 83 40 95 4f 22 40 99 35 69 40 9d 21 42 40 a1 12 84 40 a5 09 18 40 a9 04 ff 40 ad 06 25 40 b1 0c 5f }

  condition:
    $a0
}