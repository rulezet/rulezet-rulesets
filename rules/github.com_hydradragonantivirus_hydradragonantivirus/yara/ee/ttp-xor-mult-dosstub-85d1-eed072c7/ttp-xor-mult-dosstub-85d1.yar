rule TTP_XOR_MULT_DOSStub_85d1 {
  strings:
    $key_85d1 = { d1 b9 [2] a5 a1 [2] e2 a3 [2] a5 b2 [2] eb be [2] e7 b4 [2] f0 bf [2] eb f1 [2] d6 }

  condition:
    any of them
}