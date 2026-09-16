rule libavcodec_dca_lossless_quant_d__flt32___32_lil_128_ {
  strings:
    $a0 = { 00 00 00 00 00 00 80 3f 00 00 00 3f c3 f5 a8 3e 00 00 80 3e e7 fb 29 3e 00 00 00 3e e7 fb a9 3d 00 00 80 3d 00 00 00 3d 24 97 7f 3c f3 01 01 3c 1f 84 80 3b 03 41 00 3b 75 1f 80 3a ae 0e 00 3a f8 07 80 39 f8 07 00 39 9a 02 80 38 9a 02 00 38 9a 02 80 37 9c fc ff 36 9a 02 80 36 05 f4 ff 35 e2 00 80 35 e5 fa ff 34 e5 fa 7f 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}