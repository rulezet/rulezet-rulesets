rule TTP_XOR_MULT_DOSStub_14b6 {
  strings:
    $key_14b6 = { 40 de [2] 34 c6 [2] 73 c4 [2] 34 d5 [2] 7a d9 [2] 76 d3 [2] 61 d8 [2] 7a 96 [2] 47 }

  condition:
    any of them
}