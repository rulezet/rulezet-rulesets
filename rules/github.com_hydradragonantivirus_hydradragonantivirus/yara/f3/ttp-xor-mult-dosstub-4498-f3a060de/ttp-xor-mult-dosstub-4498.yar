rule TTP_XOR_MULT_DOSStub_4498 {
  strings:
    $key_4498 = { 10 f0 [2] 64 e8 [2] 23 ea [2] 64 fb [2] 2a f7 [2] 26 fd [2] 31 f6 [2] 2a b8 [2] 17 }

  condition:
    any of them
}