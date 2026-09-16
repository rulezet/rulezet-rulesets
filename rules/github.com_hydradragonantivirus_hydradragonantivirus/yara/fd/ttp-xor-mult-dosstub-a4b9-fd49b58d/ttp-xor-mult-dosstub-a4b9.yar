rule TTP_XOR_MULT_DOSStub_a4b9 {
  strings:
    $key_a4b9 = { f0 d1 [2] 84 c9 [2] c3 cb [2] 84 da [2] ca d6 [2] c6 dc [2] d1 d7 [2] ca 99 [2] f7 }

  condition:
    any of them
}