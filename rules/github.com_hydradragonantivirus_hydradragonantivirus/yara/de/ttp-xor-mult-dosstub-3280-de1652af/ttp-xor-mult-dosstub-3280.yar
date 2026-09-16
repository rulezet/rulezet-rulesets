rule TTP_XOR_MULT_DOSStub_3280 {
  strings:
    $key_3280 = { 66 e8 [2] 12 f0 [2] 55 f2 [2] 12 e3 [2] 5c ef [2] 50 e5 [2] 47 ee [2] 5c a0 [2] 61 }

  condition:
    any of them
}