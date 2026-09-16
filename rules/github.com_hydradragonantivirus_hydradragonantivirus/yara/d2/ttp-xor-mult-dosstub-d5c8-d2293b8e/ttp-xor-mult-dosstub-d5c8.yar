rule TTP_XOR_MULT_DOSStub_d5c8 {
  strings:
    $key_d5c8 = { 81 a0 [2] f5 b8 [2] b2 ba [2] f5 ab [2] bb a7 [2] b7 ad [2] a0 a6 [2] bb e8 [2] 86 }

  condition:
    any of them
}