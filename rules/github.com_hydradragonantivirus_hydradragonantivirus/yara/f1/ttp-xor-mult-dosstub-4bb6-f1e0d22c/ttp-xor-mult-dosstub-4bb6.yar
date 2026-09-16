rule TTP_XOR_MULT_DOSStub_4bb6 {
  strings:
    $key_4bb6 = { 1f de [2] 6b c6 [2] 2c c4 [2] 6b d5 [2] 25 d9 [2] 29 d3 [2] 3e d8 [2] 25 96 [2] 18 }

  condition:
    any of them
}