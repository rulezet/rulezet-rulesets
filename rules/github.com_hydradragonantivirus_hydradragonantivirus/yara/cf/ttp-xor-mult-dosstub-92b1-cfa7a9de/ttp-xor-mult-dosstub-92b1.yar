rule TTP_XOR_MULT_DOSStub_92b1 {
  strings:
    $key_92b1 = { c6 d9 [2] b2 c1 [2] f5 c3 [2] b2 d2 [2] fc de [2] f0 d4 [2] e7 df [2] fc 91 [2] c1 }

  condition:
    any of them
}