rule TTP_XOR_MULT_DOSStub_c5b0 {
  strings:
    $key_c5b0 = { 91 d8 [2] e5 c0 [2] a2 c2 [2] e5 d3 [2] ab df [2] a7 d5 [2] b0 de [2] ab 90 [2] 96 }

  condition:
    any of them
}