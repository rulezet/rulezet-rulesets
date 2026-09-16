rule TTP_XOR_MULT_DOSStub_f2d4 {
  strings:
    $key_f2d4 = { a6 bc [2] d2 a4 [2] 95 a6 [2] d2 b7 [2] 9c bb [2] 90 b1 [2] 87 ba [2] 9c f4 [2] a1 }

  condition:
    any of them
}