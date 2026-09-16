rule libfaad2_f_huff_ipd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 E2 04 05 06 E5 E6 E4 E7 E3 E8 }

  condition:
    $a0
}