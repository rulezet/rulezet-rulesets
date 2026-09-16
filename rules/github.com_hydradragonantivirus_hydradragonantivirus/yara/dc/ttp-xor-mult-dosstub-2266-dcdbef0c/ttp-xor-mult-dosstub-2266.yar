rule TTP_XOR_MULT_DOSStub_2266 {
  strings:
    $key_2266 = { 76 0e [2] 02 16 [2] 45 14 [2] 02 05 [2] 4c 09 [2] 40 03 [2] 57 08 [2] 4c 46 [2] 71 }

  condition:
    any of them
}