rule TTP_XOR_MULT_DOSStub_a1b9 {
  strings:
    $key_a1b9 = { f5 d1 [2] 81 c9 [2] c6 cb [2] 81 da [2] cf d6 [2] c3 dc [2] d4 d7 [2] cf 99 [2] f2 }

  condition:
    any of them
}