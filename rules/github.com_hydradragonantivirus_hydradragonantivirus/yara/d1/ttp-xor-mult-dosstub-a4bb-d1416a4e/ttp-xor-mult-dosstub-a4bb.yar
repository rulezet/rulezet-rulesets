rule TTP_XOR_MULT_DOSStub_a4bb {
  strings:
    $key_a4bb = { f0 d3 [2] 84 cb [2] c3 c9 [2] 84 d8 [2] ca d4 [2] c6 de [2] d1 d5 [2] ca 9b [2] f7 }

  condition:
    any of them
}