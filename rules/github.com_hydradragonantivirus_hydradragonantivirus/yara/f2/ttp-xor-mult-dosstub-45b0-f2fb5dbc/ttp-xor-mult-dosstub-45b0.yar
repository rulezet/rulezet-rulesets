rule TTP_XOR_MULT_DOSStub_45b0 {
  strings:
    $key_45b0 = { 11 d8 [2] 65 c0 [2] 22 c2 [2] 65 d3 [2] 2b df [2] 27 d5 [2] 30 de [2] 2b 90 [2] 16 }

  condition:
    any of them
}