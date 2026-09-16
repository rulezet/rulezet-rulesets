rule TTP_XOR_MULT_DOSStub_d2b6 {
  strings:
    $key_d2b6 = { 86 de [2] f2 c6 [2] b5 c4 [2] f2 d5 [2] bc d9 [2] b0 d3 [2] a7 d8 [2] bc 96 [2] 81 }

  condition:
    any of them
}