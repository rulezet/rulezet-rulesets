rule TTP_XOR_MULT_DOSStub_5461 {
  strings:
    $key_5461 = { 00 09 [2] 74 11 [2] 33 13 [2] 74 02 [2] 3a 0e [2] 36 04 [2] 21 0f [2] 3a 41 [2] 07 }

  condition:
    any of them
}