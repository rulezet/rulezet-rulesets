rule TTP_XOR_MULT_DOSStub_23b6 {
  strings:
    $key_23b6 = { 77 de [2] 03 c6 [2] 44 c4 [2] 03 d5 [2] 4d d9 [2] 41 d3 [2] 56 d8 [2] 4d 96 [2] 70 }

  condition:
    any of them
}