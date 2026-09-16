rule MPEG_4_ALS_decoder_mcc_weightings__16_lil_64_ {
  strings:
    $a0 = { CC 00 C0 00 B3 00 A6 00 99 00 8C 00 80 00 73 00 66 00 59 00 4C 00 40 00 33 00 26 00 19 00 0C 00 00 00 F4 FF E7 FF DA FF CD FF C0 FF B4 FF A7 FF 9A FF 8D FF 80 FF 74 FF 67 FF 5A FF 4D FF 40 FF }

  condition:
    $a0
}