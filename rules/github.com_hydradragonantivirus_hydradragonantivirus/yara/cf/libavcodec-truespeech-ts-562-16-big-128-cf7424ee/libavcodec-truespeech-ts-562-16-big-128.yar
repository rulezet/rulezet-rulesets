rule libavcodec_truespeech_ts_562__16_big_128_ {
  strings:
    $a0 = { 00 02 00 06 ff fe ff fa 00 04 00 0c ff fc ff f4 00 06 00 12 ff fa ff ee 00 0a 00 1e ff f6 ff e2 00 10 00 30 ff f0 ff d0 00 19 00 4b ff e7 ff b5 00 28 00 78 ff d8 ff 88 00 40 00 c0 ff c0 ff 40 00 65 01 2f ff 9b fe d1 00 a1 01 e3 ff 5f fe 1d 01 00 03 00 ff 00 fd 00 01 96 04 c2 fe 6a fb 3e 02 85 07 8f fd 7b f8 71 04 00 0c 00 fc 00 f4 00 06 59 13 0b f9 a7 ec f5 0a 14 1e 3c f5 ec e1 c4 }

  condition:
    $a0
}