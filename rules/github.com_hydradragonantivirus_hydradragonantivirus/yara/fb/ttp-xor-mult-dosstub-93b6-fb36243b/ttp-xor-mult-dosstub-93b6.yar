rule TTP_XOR_MULT_DOSStub_93b6 {
  strings:
    $key_93b6 = { c7 de [2] b3 c6 [2] f4 c4 [2] b3 d5 [2] fd d9 [2] f1 d3 [2] e6 d8 [2] fd 96 [2] c0 }

  condition:
    any of them
}