rule TTP_XOR_MULT_DOSStub_f2c7 {
  strings:
    $key_f2c7 = { a6 af [2] d2 b7 [2] 95 b5 [2] d2 a4 [2] 9c a8 [2] 90 a2 [2] 87 a9 [2] 9c e7 [2] a1 }

  condition:
    any of them
}