rule TTP_XOR_MULT_DOSStub_a1bb {
  strings:
    $key_a1bb = { f5 d3 [2] 81 cb [2] c6 c9 [2] 81 d8 [2] cf d4 [2] c3 de [2] d4 d5 [2] cf 9b [2] f2 }

  condition:
    any of them
}