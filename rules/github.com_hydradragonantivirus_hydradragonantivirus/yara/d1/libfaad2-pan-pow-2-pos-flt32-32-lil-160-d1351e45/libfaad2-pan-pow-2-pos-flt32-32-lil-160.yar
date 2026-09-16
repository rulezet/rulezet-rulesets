rule libfaad2_pan_pow_2_pos__flt32___32_lil_160_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f c4 9d 8f 3f c4 9d 8f 3f a8 24 a1 3f a8 24 a1 3f a8 24 a1 3f a8 24 a1 3f a8 24 a1 3f 4c de ca 3f 63 9f e3 3f 63 9f e3 3f 60 ce b4 3f 4c de ca 3f bb 65 ff 3f 6c 61 34 40 0d 64 4a 40 4c de ca 3f bc 65 ff 3f 6c 61 34 40 81 f1 8e 40 88 f1 b3 40 63 9f e3 3f 91 c3 20 40 81 f1 8e 40 c7 2d fe 40 18 85 33 41 bb 65 ff 3f 38 16 63 40 5b 89 e2 40 d8 00 62 41 75 f3 c8 41 91 c3 20 40 d8 5f a0 40 18 85 33 41 75 f3 c8 41 c9 f0 60 42 }

  condition:
    $a0
}