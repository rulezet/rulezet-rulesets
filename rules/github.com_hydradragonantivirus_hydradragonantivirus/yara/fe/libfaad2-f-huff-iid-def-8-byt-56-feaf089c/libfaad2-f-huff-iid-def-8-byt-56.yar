rule libfaad2_f_huff_iid_def__8_byt_56_ {
  strings:
    $a0 = { E1 01 02 03 E2 E0 04 05 E3 DF 06 07 E4 DE 08 09 DD E5 E6 0A DC 0B E7 0C DB 0D DA 0E E8 0F 10 11 E9 D9 12 13 EA EB 14 15 D8 EC 16 17 D7 18 19 1A D6 D3 D4 D5 ED 1B EE EF }

  condition:
    $a0
}