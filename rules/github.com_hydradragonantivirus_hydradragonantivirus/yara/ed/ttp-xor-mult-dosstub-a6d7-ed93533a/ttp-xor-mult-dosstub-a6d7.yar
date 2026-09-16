rule TTP_XOR_MULT_DOSStub_a6d7 {
  strings:
    $key_a6d7 = { f2 bf [2] 86 a7 [2] c1 a5 [2] 86 b4 [2] c8 b8 [2] c4 b2 [2] d3 b9 [2] c8 f7 [2] f5 }

  condition:
    any of them
}