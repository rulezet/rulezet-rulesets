rule TTP_XOR_MULT_DOSStub_63b6 {
  strings:
    $key_63b6 = { 37 de [2] 43 c6 [2] 04 c4 [2] 43 d5 [2] 0d d9 [2] 01 d3 [2] 16 d8 [2] 0d 96 [2] 30 }

  condition:
    any of them
}