rule TTP_XOR_MULT_DOSStub_3798 {
  strings:
    $key_3798 = { 63 f0 [2] 17 e8 [2] 50 ea [2] 17 fb [2] 59 f7 [2] 55 fd [2] 42 f6 [2] 59 b8 [2] 64 }

  condition:
    any of them
}