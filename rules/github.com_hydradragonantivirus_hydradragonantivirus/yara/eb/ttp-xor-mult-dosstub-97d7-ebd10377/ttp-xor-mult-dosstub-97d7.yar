rule TTP_XOR_MULT_DOSStub_97d7 {
  strings:
    $key_97d7 = { c3 bf [2] b7 a7 [2] f0 a5 [2] b7 b4 [2] f9 b8 [2] f5 b2 [2] e2 b9 [2] f9 f7 [2] c4 }

  condition:
    any of them
}