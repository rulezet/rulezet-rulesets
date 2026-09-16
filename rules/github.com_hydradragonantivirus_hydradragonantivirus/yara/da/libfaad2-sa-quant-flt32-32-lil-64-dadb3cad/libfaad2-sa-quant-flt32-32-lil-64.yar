rule libfaad2_sa_quant__flt32___32_lil_64_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 a8 35 4d 3d 34 11 36 3e bc 96 90 3d 17 48 90 3e a8 c6 cb 3d dd b5 e4 3e f2 41 0f 3e e5 f2 0f 3f 95 65 48 3e ef 38 35 3f d5 e7 8a 3e 3d 2c 64 3f 88 63 bd 3e 00 00 80 3f }

  condition:
    $a0
}