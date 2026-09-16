rule TTP_XOR_MULT_DOSStub_96b4 {
  strings:
    $key_96b4 = { c2 dc [2] b6 c4 [2] f1 c6 [2] b6 d7 [2] f8 db [2] f4 d1 [2] e3 da [2] f8 94 [2] c5 }

  condition:
    any of them
}