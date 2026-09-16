rule libavcodec_truespeech_ts_562__16_lil_128_ {
  strings:
    $a0 = { 02 00 06 00 fe ff fa ff 04 00 0c 00 fc ff f4 ff 06 00 12 00 fa ff ee ff 0a 00 1e 00 f6 ff e2 ff 10 00 30 00 f0 ff d0 ff 19 00 4b 00 e7 ff b5 ff 28 00 78 00 d8 ff 88 ff 40 00 c0 00 c0 ff 40 ff 65 00 2f 01 9b ff d1 fe a1 00 e3 01 5f ff 1d fe 00 01 00 03 00 ff 00 fd 96 01 c2 04 6a fe 3e fb 85 02 8f 07 7b fd 71 f8 00 04 00 0c 00 fc 00 f4 59 06 0b 13 a7 f9 f5 ec 14 0a 3c 1e ec f5 c4 e1 }

  condition:
    $a0
}