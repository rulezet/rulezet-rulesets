rule TTP_XOR_MULT_DOSStub_92b4 {
  strings:
    $key_92b4 = { c6 dc [2] b2 c4 [2] f5 c6 [2] b2 d7 [2] fc db [2] f0 d1 [2] e7 da [2] fc 94 [2] c1 }

  condition:
    any of them
}