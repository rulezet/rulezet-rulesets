rule MPEG_2_NBC_Fraunhofer_sfb_16_120__16_big_30_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 28 00 30 00 3c 00 48 00 58 00 6c 00 78 }

  condition:
    $a0
}