rule libavcodec_truespeech_ts_cb_3__16_lil_32_ {
  strings:
    $a0 = { 54 c6 f2 de aa ef 94 fd 6a 09 3f 14 7b 1e 2c 28 76 31 89 3a 9f 43 a2 4c 7f 55 50 5e 18 67 8d 6f }

  condition:
    $a0
}