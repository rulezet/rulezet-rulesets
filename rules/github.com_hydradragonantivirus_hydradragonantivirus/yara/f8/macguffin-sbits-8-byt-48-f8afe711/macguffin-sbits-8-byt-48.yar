rule MacGuffin_sbits__8_byt_48_ {
  strings:
    $a0 = { 02 05 06 09 0b 0d 01 04 07 0a 08 0e 03 06 08 0d 00 0f 0c 0e 01 02 04 0a 00 0a 03 0e 06 0c 07 08 0c 0f 01 05 09 0f 05 0b 02 07 0b 0d 00 04 03 09 }

  condition:
    $a0
}