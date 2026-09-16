rule TTP_XOR_MULT_DOSStub_a2d6 {
  strings:
    $key_a2d6 = { f6 be [2] 82 a6 [2] c5 a4 [2] 82 b5 [2] cc b9 [2] c0 b3 [2] d7 b8 [2] cc f6 [2] f1 }

  condition:
    any of them
}