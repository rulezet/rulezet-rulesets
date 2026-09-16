rule TTP_XOR_MULT_DOSStub_81b0 {
  strings:
    $key_81b0 = { d5 d8 [2] a1 c0 [2] e6 c2 [2] a1 d3 [2] ef df [2] e3 d5 [2] f4 de [2] ef 90 [2] d2 }

  condition:
    any of them
}