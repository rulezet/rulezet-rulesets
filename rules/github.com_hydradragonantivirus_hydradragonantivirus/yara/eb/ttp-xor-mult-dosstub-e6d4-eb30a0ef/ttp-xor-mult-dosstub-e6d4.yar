rule TTP_XOR_MULT_DOSStub_e6d4 {
  strings:
    $key_e6d4 = { b2 bc [2] c6 a4 [2] 81 a6 [2] c6 b7 [2] 88 bb [2] 84 b1 [2] 93 ba [2] 88 f4 [2] b5 }

  condition:
    any of them
}