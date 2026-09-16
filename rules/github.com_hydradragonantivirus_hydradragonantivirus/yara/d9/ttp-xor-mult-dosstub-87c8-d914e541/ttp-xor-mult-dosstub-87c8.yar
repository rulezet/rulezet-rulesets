rule TTP_XOR_MULT_DOSStub_87c8 {
  strings:
    $key_87c8 = { d3 a0 [2] a7 b8 [2] e0 ba [2] a7 ab [2] e9 a7 [2] e5 ad [2] f2 a6 [2] e9 e8 [2] d4 }

  condition:
    any of them
}