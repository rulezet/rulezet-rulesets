rule TTP_XOR_MULT_DOSStub_a1d1 {
  strings:
    $key_a1d1 = { f5 b9 [2] 81 a1 [2] c6 a3 [2] 81 b2 [2] cf be [2] c3 b4 [2] d4 bf [2] cf f1 [2] f2 }

  condition:
    any of them
}