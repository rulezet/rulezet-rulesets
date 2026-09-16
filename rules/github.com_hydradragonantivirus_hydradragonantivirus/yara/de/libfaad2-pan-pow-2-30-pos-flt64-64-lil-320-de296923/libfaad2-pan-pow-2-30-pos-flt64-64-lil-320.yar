rule libfaad2_pan_pow_2_30_pos__flt64___64_lil_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 03 8f a2 e0 bf 0f f0 3f 03 8f a2 e0 bf 0f f0 3f e0 4c 5b 42 8f 1f f0 3f e0 4c 5b 42 8f 1f f0 3f e0 4c 5b 42 8f 1f f0 3f e0 4c 5b 42 8f 1f f0 3f e0 4c 5b 42 8f 1f f0 3f 77 0e a7 c4 5c 3f f0 3f 96 cf 18 04 5b 4f f0 3f 96 cf 18 04 5b 4f f0 3f a4 13 a9 33 6e 2f f0 3f 77 0e a7 c4 5c 3f f0 3f fa c9 d4 01 69 5f f0 3f ef 7b 64 0b f2 8f f0 3f c2 7e 2c 9d 3f a0 f0 3f 77 0e a7 c4 5c 3f f0 3f fa c9 d4 01 69 5f f0 3f ef 7b 64 0b f2 8f f0 3f 07 b7 7d db 88 d1 f0 3f fe ce 29 da b2 f2 f0 3f 96 cf 18 04 5b 4f f0 3f 5c e5 e8 75 b4 7f f0 3f 07 b7 7d db 88 d1 f0 3f ea 04 e8 82 f0 24 f1 3f 78 63 9c 1a c3 57 f1 3f fa c9 d4 01 69 5f f0 3f fd 18 5c 3b 9d b0 f0 3f 66 4c c6 d3 20 14 f1 3f 28 0a 06 6d f8 79 f1 3f f8 d8 bb 11 a6 d0 f1 3f 5c e5 e8 75 b4 7f f0 3f 67 43 ef 6e 14 e2 f0 3f 78 63 9c 1a c3 57 f1 3f f8 d8 bb 11 a6 d0 f1 3f a6 7e fa a9 d3 4c f2 3f }

  condition:
    $a0
}