rule TTP_XOR_MULT_DOSStub_f2c0 {
  strings:
    $key_f2c0 = { a6 a8 [2] d2 b0 [2] 95 b2 [2] d2 a3 [2] 9c af [2] 90 a5 [2] 87 ae [2] 9c e0 [2] a1 }

  condition:
    any of them
}