rule TTP_XOR_MULT_DOSStub_96f6 {
  strings:
    $key_96f6 = { c2 9e [2] b6 86 [2] f1 84 [2] b6 95 [2] f8 99 [2] f4 93 [2] e3 98 [2] f8 d6 [2] c5 }

  condition:
    any of them
}