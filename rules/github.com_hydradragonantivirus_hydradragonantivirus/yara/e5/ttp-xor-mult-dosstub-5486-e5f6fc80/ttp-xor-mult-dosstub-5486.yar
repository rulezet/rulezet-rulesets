rule TTP_XOR_MULT_DOSStub_5486 {
  strings:
    $key_5486 = { 00 ee [2] 74 f6 [2] 33 f4 [2] 74 e5 [2] 3a e9 [2] 36 e3 [2] 21 e8 [2] 3a a6 [2] 07 }

  condition:
    any of them
}