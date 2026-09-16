rule libfaad2_t_huff_icc__8_byt_28_ {
  strings:
    $a0 = { E1 01 E2 02 E0 03 E3 04 DF 05 E4 06 DE 07 E5 08 DD 09 E6 0A DC 0B E7 0C DB 0D DA E8 }

  condition:
    $a0
}