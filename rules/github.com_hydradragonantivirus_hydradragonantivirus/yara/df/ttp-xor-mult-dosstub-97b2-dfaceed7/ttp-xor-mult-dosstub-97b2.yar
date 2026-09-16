rule TTP_XOR_MULT_DOSStub_97b2 {
  strings:
    $key_97b2 = { c3 da [2] b7 c2 [2] f0 c0 [2] b7 d1 [2] f9 dd [2] f5 d7 [2] e2 dc [2] f9 92 [2] c4 }

  condition:
    any of them
}