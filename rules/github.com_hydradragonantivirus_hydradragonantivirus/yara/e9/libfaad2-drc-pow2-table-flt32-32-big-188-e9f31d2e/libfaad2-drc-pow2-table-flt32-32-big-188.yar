rule libfaad2_drc_pow2_table__flt32___32_big_188_ {
  strings:
    $a0 = { 3f 03 c0 2d 3f 07 9c 7d 3f 0b 95 c2 3f 0f ac d6 3f 13 e2 99 3f 18 37 f0 3f 1c ad c9 3f 21 45 18 3f 25 fe d7 3f 2a dc 08 3f 2f dd b7 3f 35 04 f3 3f 3a 52 d8 3f 3f c8 87 3f 45 67 2a 3f 4b 2f f5 3f 51 24 24 3f 57 44 fd 3f 5d 93 ce 3f 64 11 f0 3f 6a c0 c7 3f 71 a1 bf 3f 78 b6 51 3f 80 00 00 3f 83 c0 2d 3f 87 9c 7d 3f 8b 95 c2 3f 8f ac d6 3f 93 e2 99 3f 98 37 f0 3f 9c ad c9 3f a1 45 18 3f a5 fe d7 3f aa dc 08 3f af dd b7 3f b5 04 f3 3f ba 52 d8 3f bf c8 87 3f c5 67 2a 3f cb 2f f5 3f d1 24 24 3f d7 44 fd 3f dd 93 ce 3f e4 11 f0 3f ea c0 c7 3f f1 a1 bf 3f f8 b6 51 }

  condition:
    $a0
}