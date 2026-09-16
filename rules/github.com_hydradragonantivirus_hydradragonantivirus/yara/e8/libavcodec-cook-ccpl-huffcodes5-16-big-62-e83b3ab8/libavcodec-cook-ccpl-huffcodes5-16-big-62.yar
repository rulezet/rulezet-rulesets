rule libavcodec_COOK_ccpl_huffcodes5__16_big_62_ {
  strings:
    $a0 = { 03 f8 03 f9 03 fa 03 fb 01 f8 01 f9 00 f8 00 f9 00 78 00 79 00 38 00 39 00 18 00 19 00 04 00 00 00 05 00 1a 00 1b 00 3a 00 3b 00 7a 00 7b 00 fa 00 fb 01 fa 01 fb 03 fc 03 fd 03 fe 03 ff }

  condition:
    $a0
}