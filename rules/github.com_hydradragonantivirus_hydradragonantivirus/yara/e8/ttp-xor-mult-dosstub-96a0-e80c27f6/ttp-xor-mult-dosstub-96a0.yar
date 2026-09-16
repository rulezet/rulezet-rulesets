rule TTP_XOR_MULT_DOSStub_96a0 {
  strings:
    $key_96a0 = { c2 c8 [2] b6 d0 [2] f1 d2 [2] b6 c3 [2] f8 cf [2] f4 c5 [2] e3 ce [2] f8 80 [2] c5 }

  condition:
    any of them
}