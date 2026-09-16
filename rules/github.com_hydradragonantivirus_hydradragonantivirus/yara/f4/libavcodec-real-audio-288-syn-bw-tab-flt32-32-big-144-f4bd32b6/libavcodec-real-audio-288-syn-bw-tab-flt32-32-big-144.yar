rule libavcodec_real_audio_288_syn_bw_tab__flt32___32_big_144_ {
  strings:
    $a0 = { 3f 7d 00 00 3f 7a 09 00 3f 77 1a e5 3f 74 35 94 3f 71 58 f3 3f 6e 84 e8 3f 6b b9 59 3f 68 f6 2d 3f 66 3b 4a 3f 63 88 98 3f 60 dd fe 3f 5e 3b 64 3f 5b a0 b2 3f 59 0d d0 3f 56 82 a7 3f 53 ff 1f 3f 51 83 22 3f 4f 0e 99 3f 4c a1 6d 3f 4a 3b 89 3f 47 dc d6 3f 45 85 3f 3f 43 34 af 3f 40 eb 11 3f 3e a8 50 3f 3c 6c 57 3f 3a 37 12 3f 38 08 6d 3f 35 e0 54 3f 33 be b3 3f 31 a3 77 3f 2f 8e 8d 3f 2d 7f e1 3f 2b 77 61 3f 29 74 fb 3f 27 78 9c }

  condition:
    $a0
}