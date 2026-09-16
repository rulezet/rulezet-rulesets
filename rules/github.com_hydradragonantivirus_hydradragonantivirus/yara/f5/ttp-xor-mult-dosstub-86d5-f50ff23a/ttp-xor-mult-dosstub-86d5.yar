rule TTP_XOR_MULT_DOSStub_86d5 {
  strings:
    $key_86d5 = { d2 bd [2] a6 a5 [2] e1 a7 [2] a6 b6 [2] e8 ba [2] e4 b0 [2] f3 bb [2] e8 f5 [2] d5 }

  condition:
    any of them
}