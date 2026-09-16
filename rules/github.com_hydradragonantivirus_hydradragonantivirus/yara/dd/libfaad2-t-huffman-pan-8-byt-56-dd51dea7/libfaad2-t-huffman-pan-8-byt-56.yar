rule libfaad2_t_huffman_pan__8_byt_56_ {
  strings:
    $a0 = { F1 01 F0 02 F2 03 EF 04 F3 05 EE 06 F4 07 ED 08 F5 09 0A 0B EC F6 0C 0D EB F7 0E 0F EA F8 10 11 E9 F9 12 13 E7 FB 14 15 E8 FA 16 17 18 19 1A 1B E3 E4 E5 E6 FC FD FE FF }

  condition:
    $a0
}