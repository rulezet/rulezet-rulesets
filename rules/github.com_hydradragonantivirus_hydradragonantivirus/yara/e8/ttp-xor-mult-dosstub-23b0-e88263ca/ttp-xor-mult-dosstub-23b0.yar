rule TTP_XOR_MULT_DOSStub_23b0 {
  strings:
    $key_23b0 = { 77 d8 [2] 03 c0 [2] 44 c2 [2] 03 d3 [2] 4d df [2] 41 d5 [2] 56 de [2] 4d 90 [2] 70 }

  condition:
    any of them
}