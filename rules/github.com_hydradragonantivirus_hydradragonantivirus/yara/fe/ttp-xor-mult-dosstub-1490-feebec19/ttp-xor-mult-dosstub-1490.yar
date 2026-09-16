rule TTP_XOR_MULT_DOSStub_1490 {
  strings:
    $key_1490 = { 40 f8 [2] 34 e0 [2] 73 e2 [2] 34 f3 [2] 7a ff [2] 76 f5 [2] 61 fe [2] 7a b0 [2] 47 }

  condition:
    any of them
}