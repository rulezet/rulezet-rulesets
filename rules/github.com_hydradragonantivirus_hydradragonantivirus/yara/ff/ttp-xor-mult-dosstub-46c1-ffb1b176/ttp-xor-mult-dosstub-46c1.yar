rule TTP_XOR_MULT_DOSStub_46c1 {
  strings:
    $key_46c1 = { 12 a9 [2] 66 b1 [2] 21 b3 [2] 66 a2 [2] 28 ae [2] 24 a4 [2] 33 af [2] 28 e1 [2] 15 }

  condition:
    any of them
}