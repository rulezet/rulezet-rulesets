rule TTP_XOR_MULT_DOSStub_59b6 {
  strings:
    $key_59b6 = { 0d de [2] 79 c6 [2] 3e c4 [2] 79 d5 [2] 37 d9 [2] 3b d3 [2] 2c d8 [2] 37 96 [2] 0a }

  condition:
    any of them
}