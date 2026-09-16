rule TTP_XOR_MULT_DOSStub_5481 {
  strings:
    $key_5481 = { 00 e9 [2] 74 f1 [2] 33 f3 [2] 74 e2 [2] 3a ee [2] 36 e4 [2] 21 ef [2] 3a a1 [2] 07 }

  condition:
    any of them
}