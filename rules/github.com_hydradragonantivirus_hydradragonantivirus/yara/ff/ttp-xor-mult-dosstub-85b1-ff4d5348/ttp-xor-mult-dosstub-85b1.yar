rule TTP_XOR_MULT_DOSStub_85b1 {
  strings:
    $key_85b1 = { d1 d9 [2] a5 c1 [2] e2 c3 [2] a5 d2 [2] eb de [2] e7 d4 [2] f0 df [2] eb 91 [2] d6 }

  condition:
    any of them
}