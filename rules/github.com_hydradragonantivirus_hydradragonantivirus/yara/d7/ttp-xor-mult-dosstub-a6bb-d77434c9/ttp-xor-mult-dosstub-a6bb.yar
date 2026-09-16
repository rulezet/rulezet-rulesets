rule TTP_XOR_MULT_DOSStub_a6bb {
  strings:
    $key_a6bb = { f2 d3 [2] 86 cb [2] c1 c9 [2] 86 d8 [2] c8 d4 [2] c4 de [2] d3 d5 [2] c8 9b [2] f5 }

  condition:
    any of them
}