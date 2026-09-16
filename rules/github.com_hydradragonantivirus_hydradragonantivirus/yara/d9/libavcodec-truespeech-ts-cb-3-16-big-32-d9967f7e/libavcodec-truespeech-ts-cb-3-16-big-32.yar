rule libavcodec_truespeech_ts_cb_3__16_big_32_ {
  strings:
    $a0 = { c6 54 de f2 ef aa fd 94 09 6a 14 3f 1e 7b 28 2c 31 76 3a 89 43 9f 4c a2 55 7f 5e 50 67 18 6f 8d }

  condition:
    $a0
}