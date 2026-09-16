rule TTP_XOR_MULT_DOSStub_0280 {
  strings:
    $key_0280 = { 56 e8 [2] 22 f0 [2] 65 f2 [2] 22 e3 [2] 6c ef [2] 60 e5 [2] 77 ee [2] 6c a0 [2] 51 }

  condition:
    any of them
}