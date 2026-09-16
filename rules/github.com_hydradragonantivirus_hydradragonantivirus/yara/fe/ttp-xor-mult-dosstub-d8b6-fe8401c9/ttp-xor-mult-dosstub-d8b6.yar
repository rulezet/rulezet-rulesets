rule TTP_XOR_MULT_DOSStub_d8b6 {
  strings:
    $key_d8b6 = { 8c de [2] f8 c6 [2] bf c4 [2] f8 d5 [2] b6 d9 [2] ba d3 [2] ad d8 [2] b6 96 [2] 8b }

  condition:
    any of them
}