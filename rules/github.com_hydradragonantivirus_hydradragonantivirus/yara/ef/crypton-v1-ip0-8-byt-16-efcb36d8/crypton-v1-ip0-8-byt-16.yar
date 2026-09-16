rule Crypton_v1_ip0__8_byt_16_ {
  strings:
    $a0 = { 0c 03 0a 09 0e 05 0d 0b 06 08 02 04 0f 07 01 00 }

  condition:
    $a0
}