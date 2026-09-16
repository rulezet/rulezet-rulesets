rule TTP_XOR_MULT_DOSStub_b6d4 {
  strings:
    $key_b6d4 = { e2 bc [2] 96 a4 [2] d1 a6 [2] 96 b7 [2] d8 bb [2] d4 b1 [2] c3 ba [2] d8 f4 [2] e5 }

  condition:
    any of them
}