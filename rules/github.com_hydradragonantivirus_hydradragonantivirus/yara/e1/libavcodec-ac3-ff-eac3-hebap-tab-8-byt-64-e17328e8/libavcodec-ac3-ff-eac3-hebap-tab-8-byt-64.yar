rule libavcodec_AC3_ff_eac3_hebap_tab__8_byt_64_ {
  strings:
    $a0 = { 00 01 02 03 04 05 06 07 08 08 08 08 09 09 09 0a 0a 0a 0a 0b 0b 0b 0b 0c 0c 0c 0c 0d 0d 0d 0d 0e 0e 0e 0e 0f 0f 0f 0f 10 10 10 10 11 11 11 11 12 12 12 12 12 12 12 12 13 13 13 13 13 13 13 13 13 }

  condition:
    $a0
}