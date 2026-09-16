rule TTP_XOR_MULT_DOSStub_49b6 {
  strings:
    $key_49b6 = { 1d de [2] 69 c6 [2] 2e c4 [2] 69 d5 [2] 27 d9 [2] 2b d3 [2] 3c d8 [2] 27 96 [2] 1a }

  condition:
    any of them
}