rule TTP_XOR_MULT_DOSStub_5580 {
  strings:
    $key_5580 = { 01 e8 [2] 75 f0 [2] 32 f2 [2] 75 e3 [2] 3b ef [2] 37 e5 [2] 20 ee [2] 3b a0 [2] 06 }

  condition:
    any of them
}