rule TTP_XOR_MULT_DOSStub_a0bb {
  strings:
    $key_a0bb = { f4 d3 [2] 80 cb [2] c7 c9 [2] 80 d8 [2] ce d4 [2] c2 de [2] d5 d5 [2] ce 9b [2] f3 }

  condition:
    any of them
}