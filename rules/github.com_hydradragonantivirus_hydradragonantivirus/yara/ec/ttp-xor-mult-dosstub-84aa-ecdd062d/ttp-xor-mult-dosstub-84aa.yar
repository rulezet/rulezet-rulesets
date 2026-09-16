rule TTP_XOR_MULT_DOSStub_84aa {
  strings:
    $key_84aa = { d0 c2 [2] a4 da [2] e3 d8 [2] a4 c9 [2] ea c5 [2] e6 cf [2] f1 c4 [2] ea 8a [2] d7 }

  condition:
    any of them
}