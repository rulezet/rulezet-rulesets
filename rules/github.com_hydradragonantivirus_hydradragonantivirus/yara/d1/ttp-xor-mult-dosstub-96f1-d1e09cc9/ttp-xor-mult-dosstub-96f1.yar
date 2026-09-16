rule TTP_XOR_MULT_DOSStub_96f1 {
  strings:
    $key_96f1 = { c2 99 [2] b6 81 [2] f1 83 [2] b6 92 [2] f8 9e [2] f4 94 [2] e3 9f [2] f8 d1 [2] c5 }

  condition:
    any of them
}