rule TTP_XOR_MULT_DOSStub_c0b6 {
  strings:
    $key_c0b6 = { 94 de [2] e0 c6 [2] a7 c4 [2] e0 d5 [2] ae d9 [2] a2 d3 [2] b5 d8 [2] ae 96 [2] 93 }

  condition:
    any of them
}