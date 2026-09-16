rule TTP_XOR_MULT_DOSStub_85d7 {
  strings:
    $key_85d7 = { d1 bf [2] a5 a7 [2] e2 a5 [2] a5 b4 [2] eb b8 [2] e7 b2 [2] f0 b9 [2] eb f7 [2] d6 }

  condition:
    any of them
}