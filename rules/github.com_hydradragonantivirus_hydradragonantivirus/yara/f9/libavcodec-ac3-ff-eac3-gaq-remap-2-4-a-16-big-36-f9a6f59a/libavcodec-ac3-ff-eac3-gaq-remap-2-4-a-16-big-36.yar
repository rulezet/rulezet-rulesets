rule libavcodec_AC3_ff_eac3_gaq_remap_2_4_a__16_big_36_ {
  strings:
    $a0 = { D5 55 ED B7 C9 25 E6 66 C4 44 E3 19 C2 11 E1 86 C1 04 E0 C2 C0 81 E0 60 C0 40 E0 30 C0 20 E0 18 C0 10 E0 0C }

  condition:
    $a0
}