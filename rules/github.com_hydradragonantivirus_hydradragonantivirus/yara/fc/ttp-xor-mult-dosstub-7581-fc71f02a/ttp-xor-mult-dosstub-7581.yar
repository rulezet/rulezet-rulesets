rule TTP_XOR_MULT_DOSStub_7581 {
  strings:
    $key_7581 = { 21 e9 [2] 55 f1 [2] 12 f3 [2] 55 e2 [2] 1b ee [2] 17 e4 [2] 00 ef [2] 1b a1 [2] 26 }

  condition:
    any of them
}