rule libfaad2_pan_quant__flt32___32_lil_160_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 16 2a 3e 1e 16 2a 3e 1e 16 aa 3e 1e 16 aa 3e 1e 16 aa 3e 1e 16 aa 3e 1e 16 aa 3e 1e 16 2a 3f a6 9b 54 3f a6 9b 54 3f 2d 21 ff 3e 1e 16 2a 3f 2d 21 7f 3f e2 58 bf 3f a6 9b d4 3f 1e 16 2a 3f 2d 21 7f 3f e2 58 bf 3f f9 31 0a 40 19 73 1f 40 a6 9b 54 3f 1e 16 aa 3f f9 31 0a 40 3f 57 3f 40 64 3b 5f 40 2d 21 7f 3f 6a de e9 3f dd b5 34 40 28 7e 74 40 89 d2 94 40 1e 16 aa 3f b7 d1 14 40 64 3b 5f 40 89 d2 94 40 5f 07 ba 40 }

  condition:
    $a0
}