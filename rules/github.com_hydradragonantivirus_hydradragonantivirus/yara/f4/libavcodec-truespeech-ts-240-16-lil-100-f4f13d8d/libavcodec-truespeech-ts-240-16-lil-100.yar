rule libavcodec_truespeech_ts_240__16_lil_100_ {
  strings:
    $a0 = { 2f ed 39 52 f1 54 a9 e4 20 26 3e ee d6 09 40 2c b5 ef e0 2b e1 3f 39 33 2f 44 fe e6 58 44 df f9 31 f2 db 43 b0 3d 05 f7 7b 4f fb fe ad 26 dc 0c c2 33 39 07 be 12 a2 43 df 1b 3e 1f 11 02 96 07 eb 2a 3f 16 0d 05 38 3a 1e 0d 78 0d 0f 15 46 33 a4 38 7d 0b 5d 2d df 1f b7 19 22 28 99 0d 12 1f 4c 19 e6 0c }

  condition:
    $a0
}