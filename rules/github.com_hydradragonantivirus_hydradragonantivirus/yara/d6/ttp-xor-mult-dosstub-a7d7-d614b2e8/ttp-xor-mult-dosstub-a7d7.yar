rule TTP_XOR_MULT_DOSStub_a7d7 {
  strings:
    $key_a7d7 = { f3 bf [2] 87 a7 [2] c0 a5 [2] 87 b4 [2] c9 b8 [2] c5 b2 [2] d2 b9 [2] c9 f7 [2] f4 }

  condition:
    any of them
}