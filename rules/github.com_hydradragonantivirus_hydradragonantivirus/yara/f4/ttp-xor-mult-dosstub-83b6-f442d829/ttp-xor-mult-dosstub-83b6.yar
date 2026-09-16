rule TTP_XOR_MULT_DOSStub_83b6 {
  strings:
    $key_83b6 = { d7 de [2] a3 c6 [2] e4 c4 [2] a3 d5 [2] ed d9 [2] e1 d3 [2] f6 d8 [2] ed 96 [2] d0 }

  condition:
    any of them
}