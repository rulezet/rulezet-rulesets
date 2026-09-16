rule libavcodec_Beam_software_vb_patterns__16_lil_128_ {
  strings:
    $a0 = { 60 06 00 ff cc cc 00 f0 88 88 0f 00 11 11 c8 fe ef 8c 7f 13 31 f7 00 c8 8c 00 13 00 00 31 00 cc cc 00 33 00 00 33 f0 0f 66 66 f0 00 00 0f 22 22 44 44 00 f6 c8 8c 6f 00 31 13 8c 31 13 c8 cc 33 00 66 c0 0c 66 00 30 03 00 f9 8c c8 9f 00 13 31 00 60 80 08 06 00 10 01 88 cc 00 fc cf 00 cc 88 3f 00 33 11 11 33 00 f3 f6 6f 03 06 c6 08 63 8c 31 c6 10 63 60 c0 36 01 6c 13 c8 36 80 6c 4c 32 }

  condition:
    $a0
}