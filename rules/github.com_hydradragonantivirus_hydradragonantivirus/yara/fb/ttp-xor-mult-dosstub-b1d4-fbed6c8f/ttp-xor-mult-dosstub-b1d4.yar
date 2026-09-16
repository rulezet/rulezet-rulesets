rule TTP_XOR_MULT_DOSStub_b1d4 {
  strings:
    $key_b1d4 = { e5 bc [2] 91 a4 [2] d6 a6 [2] 91 b7 [2] df bb [2] d3 b1 [2] c4 ba [2] df f4 [2] e2 }

  condition:
    any of them
}