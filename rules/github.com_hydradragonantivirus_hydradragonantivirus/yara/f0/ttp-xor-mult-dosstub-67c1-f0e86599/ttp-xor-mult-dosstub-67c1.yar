rule TTP_XOR_MULT_DOSStub_67c1 {
  strings:
    $key_67c1 = { 33 a9 [2] 47 b1 [2] 00 b3 [2] 47 a2 [2] 09 ae [2] 05 a4 [2] 12 af [2] 09 e1 [2] 34 }

  condition:
    any of them
}