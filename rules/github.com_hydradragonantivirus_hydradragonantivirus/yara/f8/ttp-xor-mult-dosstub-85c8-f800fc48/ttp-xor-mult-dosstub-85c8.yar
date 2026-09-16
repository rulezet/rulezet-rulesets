rule TTP_XOR_MULT_DOSStub_85c8 {
  strings:
    $key_85c8 = { d1 a0 [2] a5 b8 [2] e2 ba [2] a5 ab [2] eb a7 [2] e7 ad [2] f0 a6 [2] eb e8 [2] d6 }

  condition:
    any of them
}