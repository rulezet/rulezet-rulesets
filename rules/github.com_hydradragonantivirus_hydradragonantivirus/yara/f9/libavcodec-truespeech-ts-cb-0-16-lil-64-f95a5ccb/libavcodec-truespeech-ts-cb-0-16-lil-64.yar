rule libavcodec_truespeech_ts_cb_0__16_lil_64_ {
  strings:
    $a0 = { 40 82 64 83 ce 84 5d 86 05 88 de 89 d7 8b f4 8d 51 90 e2 92 de 95 0f 99 81 9c 79 a0 4c a5 d2 aa 8a b1 0a b9 24 c1 cc c9 39 d3 d3 dd d6 e9 93 f8 6f 09 ca 1a ec 29 1f 38 f9 45 6a 54 c3 63 b5 73 }

  condition:
    $a0
}