rule TTP_XOR_MULT_DOSStub_1498 {
  strings:
    $key_1498 = { 40 f0 [2] 34 e8 [2] 73 ea [2] 34 fb [2] 7a f7 [2] 76 fd [2] 61 f6 [2] 7a b8 [2] 47 }

  condition:
    any of them
}