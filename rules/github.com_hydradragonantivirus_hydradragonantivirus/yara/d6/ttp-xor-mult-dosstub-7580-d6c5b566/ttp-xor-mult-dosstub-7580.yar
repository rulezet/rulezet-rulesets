rule TTP_XOR_MULT_DOSStub_7580 {
  strings:
    $key_7580 = { 21 e8 [2] 55 f0 [2] 12 f2 [2] 55 e3 [2] 1b ef [2] 17 e5 [2] 00 ee [2] 1b a0 [2] 26 }

  condition:
    any of them
}