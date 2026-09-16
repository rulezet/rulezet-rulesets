rule TTP_XOR_MULT_DOSStub_7ab6 {
  strings:
    $key_7ab6 = { 2e de [2] 5a c6 [2] 1d c4 [2] 5a d5 [2] 14 d9 [2] 18 d3 [2] 0f d8 [2] 14 96 [2] 29 }

  condition:
    any of them
}