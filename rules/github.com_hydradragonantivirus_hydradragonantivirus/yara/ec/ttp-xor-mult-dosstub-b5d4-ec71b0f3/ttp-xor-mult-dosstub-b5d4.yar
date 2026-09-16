rule TTP_XOR_MULT_DOSStub_b5d4 {
  strings:
    $key_b5d4 = { e1 bc [2] 95 a4 [2] d2 a6 [2] 95 b7 [2] db bb [2] d7 b1 [2] c0 ba [2] db f4 [2] e6 }

  condition:
    any of them
}