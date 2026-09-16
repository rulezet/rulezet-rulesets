rule TTP_XOR_MULT_DOSStub_f4bb {
  strings:
    $key_f4bb = { a0 d3 [2] d4 cb [2] 93 c9 [2] d4 d8 [2] 9a d4 [2] 96 de [2] 81 d5 [2] 9a 9b [2] a7 }

  condition:
    any of them
}