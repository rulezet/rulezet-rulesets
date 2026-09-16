rule TTP_XOR_MULT_DOSStub_85b7 {
  strings:
    $key_85b7 = { d1 df [2] a5 c7 [2] e2 c5 [2] a5 d4 [2] eb d8 [2] e7 d2 [2] f0 d9 [2] eb 97 [2] d6 }

  condition:
    any of them
}