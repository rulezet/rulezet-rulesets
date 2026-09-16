rule TTP_XOR_MULT_DOSStub_96aa {
  strings:
    $key_96aa = { c2 c2 [2] b6 da [2] f1 d8 [2] b6 c9 [2] f8 c5 [2] f4 cf [2] e3 c4 [2] f8 8a [2] c5 }

  condition:
    any of them
}