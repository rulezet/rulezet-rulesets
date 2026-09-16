rule TTP_XOR_MULT_DOSStub_b0bb {
  strings:
    $key_b0bb = { e4 d3 [2] 90 cb [2] d7 c9 [2] 90 d8 [2] de d4 [2] d2 de [2] c5 d5 [2] de 9b [2] e3 }

  condition:
    any of them
}