rule TTP_XOR_MULT_DOSStub_f2c6 {
  strings:
    $key_f2c6 = { a6 ae [2] d2 b6 [2] 95 b4 [2] d2 a5 [2] 9c a9 [2] 90 a3 [2] 87 a8 [2] 9c e6 [2] a1 }

  condition:
    any of them
}