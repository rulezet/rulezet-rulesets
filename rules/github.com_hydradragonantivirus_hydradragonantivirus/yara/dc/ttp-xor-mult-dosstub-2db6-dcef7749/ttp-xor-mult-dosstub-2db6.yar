rule TTP_XOR_MULT_DOSStub_2db6 {
  strings:
    $key_2db6 = { 79 de [2] 0d c6 [2] 4a c4 [2] 0d d5 [2] 43 d9 [2] 4f d3 [2] 58 d8 [2] 43 96 [2] 7e }

  condition:
    any of them
}