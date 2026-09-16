rule TTP_XOR_MULT_DOSStub_85ca {
  strings:
    $key_85ca = { d1 a2 [2] a5 ba [2] e2 b8 [2] a5 a9 [2] eb a5 [2] e7 af [2] f0 a4 [2] eb ea [2] d6 }

  condition:
    any of them
}