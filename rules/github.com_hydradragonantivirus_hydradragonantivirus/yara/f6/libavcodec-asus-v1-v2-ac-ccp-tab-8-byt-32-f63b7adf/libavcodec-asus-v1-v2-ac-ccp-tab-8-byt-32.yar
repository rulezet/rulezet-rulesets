rule libavcodec_asus_v1_v2_ac_ccp_tab__8_byt_32_ {
  strings:
    $a0 = { 00 02 3b 06 0a 04 3a 06 02 03 39 06 3c 06 38 06 03 03 3d 06 08 04 1f 05 09 04 0b 04 0d 04 0c 04 }

  condition:
    $a0
}