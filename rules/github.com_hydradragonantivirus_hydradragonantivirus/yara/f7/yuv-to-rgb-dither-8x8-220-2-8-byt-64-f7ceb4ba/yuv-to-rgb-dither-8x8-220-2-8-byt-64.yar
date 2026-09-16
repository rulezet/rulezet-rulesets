rule YUV_to_RGB_dither_8x8_220_2__8_byt_64_ {
  strings:
    $a0 = { 00 8f 12 c8 02 9c 19 d7 4e 1c 7d 40 59 24 8a 4a 0a b4 03 a1 10 c3 08 af 6d 33 5d 26 79 3c 69 2f 01 98 17 d2 00 93 14 cd 55 21 86 47 51 1e 82 43 0e be 06 ab 0c b9 05 a6 75 39 65 2c 71 36 61 29 }

  condition:
    $a0
}