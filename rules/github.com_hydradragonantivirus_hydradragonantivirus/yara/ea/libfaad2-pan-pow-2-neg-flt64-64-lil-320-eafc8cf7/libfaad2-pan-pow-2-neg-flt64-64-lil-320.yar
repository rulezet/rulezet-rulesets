rule libfaad2_pan_pow_2_neg__flt64___64_lil_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f ce 47 63 fe 1b 85 ec 3f ce 47 63 fe 1b 85 ec 3f cf 7b ad 95 1a 6b e9 3f cf 7b ad 95 1a 6b e9 3f cf 7b ad 95 1a 6b e9 3f cf 7b ad 95 1a 6b e9 3f cf 7b ad 95 1a 6b e9 3f d9 01 7c 5c c0 30 e4 3f 17 4e 2d b6 a4 fe e1 3f 17 4e 2d b6 a4 fe e1 3f c5 71 e0 d5 72 a7 e6 3f d9 01 7c 5c c0 30 e4 3f 32 69 9d 02 aa 09 e0 3f bf 6d 5c b5 21 b5 d6 3f 7e 0a 36 64 f2 3c d4 3f d9 01 7c 5c c0 30 e4 3f 32 69 9d 02 aa 09 e0 3f bf 6d 5c b5 21 b5 d6 3f ab 74 1c e4 9a a7 cc 3f 0f a2 10 5c 40 c3 c6 3f e1 68 7d 80 a4 fe e1 3f b2 14 24 11 75 7a d9 3f ab 74 1c e4 9a a7 cc 3f 08 eb 5a d6 58 1d c0 3f f4 23 34 38 00 d1 b6 3f 32 69 9d 02 aa 09 e0 3f 8d c5 80 36 83 09 d2 3f 95 dd 27 a2 ba 14 c2 3f 93 0d b5 b7 a5 1f b2 3f d3 cd 0f 6d 11 62 a4 3f b2 14 24 11 75 7a d9 3f 7f 18 7c f5 4c 8a c9 3f a0 4d b3 e5 01 d1 b6 3f d3 cd 0f 6d 11 62 a4 3f f6 b4 c3 5f 93 35 92 3f }

  condition:
    $a0
}