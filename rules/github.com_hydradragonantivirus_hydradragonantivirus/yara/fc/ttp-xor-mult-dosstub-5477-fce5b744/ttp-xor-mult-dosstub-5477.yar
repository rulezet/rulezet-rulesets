rule TTP_XOR_MULT_DOSStub_5477 {
  strings:
    $key_5477 = { 00 1f [2] 74 07 [2] 33 05 [2] 74 14 [2] 3a 18 [2] 36 12 [2] 21 19 [2] 3a 57 [2] 07 }

  condition:
    any of them
}