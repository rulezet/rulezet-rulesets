rule TTP_XOR_MULT_DOSStub_b4bb {
  strings:
    $key_b4bb = { e0 d3 [2] 94 cb [2] d3 c9 [2] 94 d8 [2] da d4 [2] d6 de [2] c1 d5 [2] da 9b [2] e7 }

  condition:
    any of them
}