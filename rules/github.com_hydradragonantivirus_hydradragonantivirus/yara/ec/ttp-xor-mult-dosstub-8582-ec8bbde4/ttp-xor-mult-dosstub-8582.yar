rule TTP_XOR_MULT_DOSStub_8582 {
  strings:
    $key_8582 = { d1 ea [2] a5 f2 [2] e2 f0 [2] a5 e1 [2] eb ed [2] e7 e7 [2] f0 ec [2] eb a2 [2] d6 }

  condition:
    any of them
}