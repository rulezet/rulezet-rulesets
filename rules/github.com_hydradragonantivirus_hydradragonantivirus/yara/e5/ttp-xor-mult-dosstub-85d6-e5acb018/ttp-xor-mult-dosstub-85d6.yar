rule TTP_XOR_MULT_DOSStub_85d6 {
  strings:
    $key_85d6 = { d1 be [2] a5 a6 [2] e2 a4 [2] a5 b5 [2] eb b9 [2] e7 b3 [2] f0 b8 [2] eb f6 [2] d6 }

  condition:
    any of them
}