rule libavcodec_dca_lossless_quant_d__flt32___32_big_128_ {
  strings:
    $a0 = { 00 00 00 00 3f 80 00 00 3f 00 00 00 3e a8 f5 c3 3e 80 00 00 3e 29 fb e7 3e 00 00 00 3d a9 fb e7 3d 80 00 00 3d 00 00 00 3c 7f 97 24 3c 01 01 f3 3b 80 84 1f 3b 00 41 03 3a 80 1f 75 3a 00 0e ae 39 80 07 f8 39 00 07 f8 38 80 02 9a 38 00 02 9a 37 80 02 9a 36 ff fc 9c 36 80 02 9a 35 ff f4 05 35 80 00 e2 34 ff fa e5 34 7f fa e5 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}