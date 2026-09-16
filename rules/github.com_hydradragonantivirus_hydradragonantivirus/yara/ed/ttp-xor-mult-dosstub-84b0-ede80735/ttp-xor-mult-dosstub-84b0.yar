rule TTP_XOR_MULT_DOSStub_84b0 {
  strings:
    $key_84b0 = { d0 d8 [2] a4 c0 [2] e3 c2 [2] a4 d3 [2] ea df [2] e6 d5 [2] f1 de [2] ea 90 [2] d7 }

  condition:
    any of them
}