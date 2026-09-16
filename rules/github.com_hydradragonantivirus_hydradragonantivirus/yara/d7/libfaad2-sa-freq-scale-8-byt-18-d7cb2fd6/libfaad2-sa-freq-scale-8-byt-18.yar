rule libfaad2_sa_freq_scale__8_byt_18_ {
  strings:
    $a0 = { 00 00 01 01 02 02 03 03 05 05 07 07 0a 0a 0d 0d 2e 17 }

  condition:
    $a0
}