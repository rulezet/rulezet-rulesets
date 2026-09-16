rule TTP_XOR_MULT_DOSStub_5466 {
  strings:
    $key_5466 = { 00 0e [2] 74 16 [2] 33 14 [2] 74 05 [2] 3a 09 [2] 36 03 [2] 21 08 [2] 3a 46 [2] 07 }

  condition:
    any of them
}