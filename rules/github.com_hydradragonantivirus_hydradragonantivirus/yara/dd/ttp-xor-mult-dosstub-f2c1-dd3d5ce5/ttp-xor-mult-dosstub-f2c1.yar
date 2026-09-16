rule TTP_XOR_MULT_DOSStub_f2c1 {
  strings:
    $key_f2c1 = { a6 a9 [2] d2 b1 [2] 95 b3 [2] d2 a2 [2] 9c ae [2] 90 a4 [2] 87 af [2] 9c e1 [2] a1 }

  condition:
    any of them
}