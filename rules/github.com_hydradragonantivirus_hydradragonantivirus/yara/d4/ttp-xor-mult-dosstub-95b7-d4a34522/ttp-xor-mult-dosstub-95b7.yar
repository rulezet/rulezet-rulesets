rule TTP_XOR_MULT_DOSStub_95b7 {
  strings:
    $key_95b7 = { c1 df [2] b5 c7 [2] f2 c5 [2] b5 d4 [2] fb d8 [2] f7 d2 [2] e0 d9 [2] fb 97 [2] c6 }

  condition:
    any of them
}