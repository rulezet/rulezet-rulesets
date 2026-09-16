rule libavcodec_ff_alternate_vertical_scan__8_byt_64_ {
  strings:
    $a0 = { 00 08 10 18 01 09 02 0a 11 19 20 28 30 38 39 31 29 21 1a 12 03 0b 04 0c 13 1b 22 2a 32 3a 23 2b 33 3b 14 1c 05 0d 06 0e 15 1d 24 2c 34 3c 25 2d 35 3d 16 1e 07 0f 17 1f 26 2e 36 3e 27 2f 37 3f }

  condition:
    $a0
}