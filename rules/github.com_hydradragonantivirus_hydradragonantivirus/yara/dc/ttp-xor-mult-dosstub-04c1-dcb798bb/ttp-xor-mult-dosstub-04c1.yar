rule TTP_XOR_MULT_DOSStub_04c1 {
  strings:
    $key_04c1 = { 50 a9 [2] 24 b1 [2] 63 b3 [2] 24 a2 [2] 6a ae [2] 66 a4 [2] 71 af [2] 6a e1 [2] 57 }

  condition:
    any of them
}