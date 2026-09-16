rule TTP_XOR_MULT_DOSStub_a6d0 {
  strings:
    $key_a6d0 = { f2 b8 [2] 86 a0 [2] c1 a2 [2] 86 b3 [2] c8 bf [2] c4 b5 [2] d3 be [2] c8 f0 [2] f5 }

  condition:
    any of them
}