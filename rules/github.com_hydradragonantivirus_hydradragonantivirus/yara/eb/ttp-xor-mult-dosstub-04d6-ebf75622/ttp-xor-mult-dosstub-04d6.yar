rule TTP_XOR_MULT_DOSStub_04d6 {
  strings:
    $key_04d6 = { 50 be [2] 24 a6 [2] 63 a4 [2] 24 b5 [2] 6a b9 [2] 66 b3 [2] 71 b8 [2] 6a f6 [2] 57 }

  condition:
    any of them
}