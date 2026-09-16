rule TTP_XOR_MULT_DOSStub_90b0 {
  strings:
    $key_90b0 = { c4 d8 [2] b0 c0 [2] f7 c2 [2] b0 d3 [2] fe df [2] f2 d5 [2] e5 de [2] fe 90 [2] c3 }

  condition:
    any of them
}