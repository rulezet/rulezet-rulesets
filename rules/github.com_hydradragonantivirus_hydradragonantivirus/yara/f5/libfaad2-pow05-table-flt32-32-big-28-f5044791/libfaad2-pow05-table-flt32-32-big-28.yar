rule libfaad2_pow05_table__flt32___32_big_28_ {
  strings:
    $a0 = { 3f d7 44 fd 3f b5 04 f3 3f 98 37 f0 3f 80 00 00 3f 57 44 fd 3f 35 04 f3 3f 18 37 f0 }

  condition:
    $a0
}