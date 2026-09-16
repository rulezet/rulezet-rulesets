rule TTP_XOR_MULT_DOSStub_a7b9 {
  strings:
    $key_a7b9 = { f3 d1 [2] 87 c9 [2] c0 cb [2] 87 da [2] c9 d6 [2] c5 dc [2] d2 d7 [2] c9 99 [2] f4 }

  condition:
    any of them
}