rule EPWIC_s_from_var_func__flt32___32_lil_244_ {
  strings:
    $a0 = { 9b 20 9a be 5b 23 82 be b7 b6 50 be 2d d1 19 be 48 9c bf bd d8 7a 0b bd 43 8a e6 3c 83 35 be 3d 73 da 23 3e 02 f1 6a 3e 9b 20 9a 3e 8c d8 bf 3e 68 94 e6 3e 85 24 07 3f 3e 76 1b 3f a8 3a 30 3f 6e 6d 45 3f 81 0a 5b 3f 45 0e 71 3f 88 ba 83 3f e7 1d 8f 3f 79 af 9a 3f 44 6e a6 3f a3 58 b2 3f 48 6d be 3f e3 aa ca 3f 77 10 d7 3f 5e 9d e3 3f a0 4f f0 3f 3d 27 fd 3f 49 11 05 40 a5 a0 0b 40 0b 41 12 40 28 f2 18 40 a7 b3 1f 40 34 85 26 40 51 66 2d 40 d6 56 34 40 43 56 3b 40 6f 64 42 40 06 81 49 40 b4 ab 50 40 26 e4 57 40 30 2a 5f 40 aa 7d 66 40 16 de 6d 40 73 4b 75 40 6d c5 7c 40 d9 25 82 40 20 ef 85 40 62 be 89 40 8a 93 8d 40 83 6e 91 40 22 4f 95 40 69 35 99 40 42 21 9d 40 84 12 a1 40 18 09 a5 40 ff 04 a9 40 25 06 ad 40 5f 0c b1 40 }

  condition:
    $a0
}