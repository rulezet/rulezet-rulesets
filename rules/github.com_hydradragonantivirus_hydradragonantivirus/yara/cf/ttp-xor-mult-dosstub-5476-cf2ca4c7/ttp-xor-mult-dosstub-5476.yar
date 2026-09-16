rule TTP_XOR_MULT_DOSStub_5476 {
  strings:
    $key_5476 = { 00 1e [2] 74 06 [2] 33 04 [2] 74 15 [2] 3a 19 [2] 36 13 [2] 21 18 [2] 3a 56 [2] 07 }

  condition:
    any of them
}