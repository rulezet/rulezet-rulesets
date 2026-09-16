rule TTP_XOR_MULT_DOSStub_6390 {
  strings:
    $key_6390 = { 37 f8 [2] 43 e0 [2] 04 e2 [2] 43 f3 [2] 0d ff [2] 01 f5 [2] 16 fe [2] 0d b0 [2] 30 }

  condition:
    any of them
}