rule libfaad2_t_huff_ipd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 04 05 E2 E8 E6 06 E3 E7 E5 E4 }

  condition:
    $a0
}