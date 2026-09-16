rule TTP_XOR_MULT_DOSStub_92c8 {
  strings:
    $key_92c8 = { c6 a0 [2] b2 b8 [2] f5 ba [2] b2 ab [2] fc a7 [2] f0 ad [2] e7 a6 [2] fc e8 [2] c1 }

  condition:
    any of them
}