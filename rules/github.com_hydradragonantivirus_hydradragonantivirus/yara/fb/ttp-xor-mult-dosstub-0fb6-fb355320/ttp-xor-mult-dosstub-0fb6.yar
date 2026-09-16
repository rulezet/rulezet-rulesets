rule TTP_XOR_MULT_DOSStub_0fb6 {
  strings:
    $key_0fb6 = { 5b de [2] 2f c6 [2] 68 c4 [2] 2f d5 [2] 61 d9 [2] 6d d3 [2] 7a d8 [2] 61 96 [2] 5c }

  condition:
    any of them
}