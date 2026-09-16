rule TTP_XOR_MULT_DOSStub_87b1 {
  strings:
    $key_87b1 = { d3 d9 [2] a7 c1 [2] e0 c3 [2] a7 d2 [2] e9 de [2] e5 d4 [2] f2 df [2] e9 91 [2] d4 }

  condition:
    any of them
}