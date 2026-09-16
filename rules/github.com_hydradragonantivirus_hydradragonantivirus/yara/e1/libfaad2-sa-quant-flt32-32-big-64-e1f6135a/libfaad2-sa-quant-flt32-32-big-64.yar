rule libfaad2_sa_quant__flt32___32_big_64_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 3d 4d 35 a8 3e 36 11 34 3d 90 96 bc 3e 90 48 17 3d cb c6 a8 3e e4 b5 dd 3e 0f 41 f2 3f 0f f2 e5 3e 48 65 95 3f 35 38 ef 3e 8a e7 d5 3f 64 2c 3d 3e bd 63 88 3f 80 00 00 }

  condition:
    $a0
}