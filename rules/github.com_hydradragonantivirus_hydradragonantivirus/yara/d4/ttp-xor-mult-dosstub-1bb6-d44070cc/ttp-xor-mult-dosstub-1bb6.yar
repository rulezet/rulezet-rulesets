rule TTP_XOR_MULT_DOSStub_1bb6 {
  strings:
    $key_1bb6 = { 4f de [2] 3b c6 [2] 7c c4 [2] 3b d5 [2] 75 d9 [2] 79 d3 [2] 6e d8 [2] 75 96 [2] 48 }

  condition:
    any of them
}