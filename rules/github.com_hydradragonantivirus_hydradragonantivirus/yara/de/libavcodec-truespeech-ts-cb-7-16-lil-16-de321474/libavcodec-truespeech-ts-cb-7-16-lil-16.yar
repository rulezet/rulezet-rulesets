rule libavcodec_truespeech_ts_cb_7__16_lil_16_ {
  strings:
    $a0 = { f0 ce f9 e4 bb f6 46 06 f5 14 ff 23 6f 35 8d 4a }

  condition:
    $a0
}