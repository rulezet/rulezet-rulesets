rule TTP_XOR_MULT_DOSStub_d2b0 {
  strings:
    $key_d2b0 = { 86 d8 [2] f2 c0 [2] b5 c2 [2] f2 d3 [2] bc df [2] b0 d5 [2] a7 de [2] bc 90 [2] 81 }

  condition:
    any of them
}