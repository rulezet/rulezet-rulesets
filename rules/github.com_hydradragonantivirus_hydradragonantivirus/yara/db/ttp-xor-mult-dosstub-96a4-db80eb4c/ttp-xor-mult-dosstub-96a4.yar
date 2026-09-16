rule TTP_XOR_MULT_DOSStub_96a4 {
  strings:
    $key_96a4 = { c2 cc [2] b6 d4 [2] f1 d6 [2] b6 c7 [2] f8 cb [2] f4 c1 [2] e3 ca [2] f8 84 [2] c5 }

  condition:
    any of them
}