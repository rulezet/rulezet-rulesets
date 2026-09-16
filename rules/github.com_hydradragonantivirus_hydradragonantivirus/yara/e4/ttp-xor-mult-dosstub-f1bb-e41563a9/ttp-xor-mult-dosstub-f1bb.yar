rule TTP_XOR_MULT_DOSStub_f1bb {
  strings:
    $key_f1bb = { a5 d3 [2] d1 cb [2] 96 c9 [2] d1 d8 [2] 9f d4 [2] 93 de [2] 84 d5 [2] 9f 9b [2] a2 }

  condition:
    any of them
}