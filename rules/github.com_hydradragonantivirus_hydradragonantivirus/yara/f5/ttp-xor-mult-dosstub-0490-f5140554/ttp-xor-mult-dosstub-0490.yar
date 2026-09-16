rule TTP_XOR_MULT_DOSStub_0490 {
  strings:
    $key_0490 = { 50 f8 [2] 24 e0 [2] 63 e2 [2] 24 f3 [2] 6a ff [2] 66 f5 [2] 71 fe [2] 6a b0 [2] 57 }

  condition:
    any of them
}