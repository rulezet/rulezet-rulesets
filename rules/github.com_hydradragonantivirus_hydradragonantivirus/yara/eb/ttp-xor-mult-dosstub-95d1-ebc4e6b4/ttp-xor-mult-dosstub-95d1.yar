rule TTP_XOR_MULT_DOSStub_95d1 {
  strings:
    $key_95d1 = { c1 b9 [2] b5 a1 [2] f2 a3 [2] b5 b2 [2] fb be [2] f7 b4 [2] e0 bf [2] fb f1 [2] c6 }

  condition:
    any of them
}