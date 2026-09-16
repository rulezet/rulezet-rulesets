rule TTP_XOR_MULT_DOSStub_7390 {
  strings:
    $key_7390 = { 27 f8 [2] 53 e0 [2] 14 e2 [2] 53 f3 [2] 1d ff [2] 11 f5 [2] 06 fe [2] 1d b0 [2] 20 }

  condition:
    any of them
}