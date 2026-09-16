rule TTP_XOR_MULT_DOSStub_7fb6 {
  strings:
    $key_7fb6 = { 2b de [2] 5f c6 [2] 18 c4 [2] 5f d5 [2] 11 d9 [2] 1d d3 [2] 0a d8 [2] 11 96 [2] 2c }

  condition:
    any of them
}