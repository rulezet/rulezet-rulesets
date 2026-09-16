rule TTP_XOR_MULT_DOSStub_3eb6 {
  strings:
    $key_3eb6 = { 6a de [2] 1e c6 [2] 59 c4 [2] 1e d5 [2] 50 d9 [2] 5c d3 [2] 4b d8 [2] 50 96 [2] 6d }

  condition:
    any of them
}