rule libavcodec_COOK_cvh_huffcodes2__16_big_96_ {
  strings:
    $a0 = { 00 00 00 0a 00 18 00 74 00 f2 01 f4 03 f6 00 04 00 0b 00 19 00 75 00 f3 01 f5 03 f7 00 1a 00 1b 00 38 00 76 00 f4 03 f8 03 f9 00 77 00 39 00 78 00 f5 01 f6 03 fa 0f fc 00 f6 00 f7 00 f8 01 f7 03 fb 0f fd 3f fe 00 f9 01 f8 01 f9 03 fc 07 fc 7f fe ff fe 01 fa 03 fd 07 fd 0f fe 1f fe ff ff }

  condition:
    $a0
}