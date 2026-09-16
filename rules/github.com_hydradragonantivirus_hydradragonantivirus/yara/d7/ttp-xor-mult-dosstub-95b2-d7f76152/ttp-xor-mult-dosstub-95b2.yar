rule TTP_XOR_MULT_DOSStub_95b2 {
  strings:
    $key_95b2 = { c1 da [2] b5 c2 [2] f2 c0 [2] b5 d1 [2] fb dd [2] f7 d7 [2] e0 dc [2] fb 92 [2] c6 }

  condition:
    any of them
}