rule TTP_XOR_MULT_DOSStub_31b6 {
  strings:
    $key_31b6 = { 65 de [2] 11 c6 [2] 56 c4 [2] 11 d5 [2] 5f d9 [2] 53 d3 [2] 44 d8 [2] 5f 96 [2] 62 }

  condition:
    any of them
}