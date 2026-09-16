rule libavcodec_COOK_cvh_huffbits5__8_byt_230_ {
  strings:
    $a0 = { 02 04 08 04 05 09 09 0a 0e 04 06 0b 05 06 0c 0a 0b 0f 09 0b 0f 0a 0d 0f 0e 0f 00 04 06 0c 06 07 0c 0c 0c 0f 05 07 0d 06 07 0d 0c 0d 0f 0a 0c 0f 0b 0d 0f 0f 0f 00 08 0d 0f 0b 0c 0f 0f 0f 00 0a 0d 0f 0c 0f 0f 0f 0f 00 0f 0f 00 0f 0f 00 00 00 00 04 05 0b 05 07 0c 0b 0c 0f 06 07 0d 07 08 0e 0c 0e 0f 0b 0d 0f 0c 0d 0f 0f 0f 00 05 06 0d 07 08 0f 0c 0e 0f 06 08 0e 07 08 0f 0e 0f 0f 0c 0c 0f 0c 0d 0f 0f 0f 00 09 0d 0f 0c 0d 0f 0f 0f 00 0b 0d 0f 0d 0d 0f 0f 0f 00 0e 0f 00 0f 0f 00 00 00 00 08 0a 0f 0b 0c 0f 0f 0f 00 0a 0c 0f 0c 0d 0f 0f 0f 00 0e 0f 00 0f 0f 00 00 00 00 08 0c 0f 0c 0d 0f 0f 0f 00 0b 0d 0f 0d 0f 0f 0f 0f 00 0f 0f 00 0f 0f 00 00 00 00 0e 0f 00 0f 0f 00 00 00 00 0f 0f 00 0f 0f }

  condition:
    $a0
}