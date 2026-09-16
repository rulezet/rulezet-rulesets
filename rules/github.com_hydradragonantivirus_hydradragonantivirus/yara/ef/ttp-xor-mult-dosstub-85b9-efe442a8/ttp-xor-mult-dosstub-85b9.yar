rule TTP_XOR_MULT_DOSStub_85b9 {
  strings:
    $key_85b9 = { d1 d1 [2] a5 c9 [2] e2 cb [2] a5 da [2] eb d6 [2] e7 dc [2] f0 d7 [2] eb 99 [2] d6 }

  condition:
    any of them
}