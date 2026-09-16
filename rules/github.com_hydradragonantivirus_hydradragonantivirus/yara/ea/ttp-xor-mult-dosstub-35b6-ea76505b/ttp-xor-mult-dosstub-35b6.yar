rule TTP_XOR_MULT_DOSStub_35b6 {
  strings:
    $key_35b6 = { 61 de [2] 15 c6 [2] 52 c4 [2] 15 d5 [2] 5b d9 [2] 57 d3 [2] 40 d8 [2] 5b 96 [2] 66 }

  condition:
    any of them
}