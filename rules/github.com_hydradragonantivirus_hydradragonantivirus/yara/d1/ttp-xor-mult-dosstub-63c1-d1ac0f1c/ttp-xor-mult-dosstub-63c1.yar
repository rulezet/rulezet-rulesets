rule TTP_XOR_MULT_DOSStub_63c1 {
  strings:
    $key_63c1 = { 37 a9 [2] 43 b1 [2] 04 b3 [2] 43 a2 [2] 0d ae [2] 01 a4 [2] 16 af [2] 0d e1 [2] 30 }

  condition:
    any of them
}