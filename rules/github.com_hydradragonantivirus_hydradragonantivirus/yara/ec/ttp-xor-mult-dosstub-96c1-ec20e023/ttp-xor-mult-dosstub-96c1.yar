rule TTP_XOR_MULT_DOSStub_96c1 {
  strings:
    $key_96c1 = { c2 a9 [2] b6 b1 [2] f1 b3 [2] b6 a2 [2] f8 ae [2] f4 a4 [2] e3 af [2] f8 e1 [2] c5 }

  condition:
    any of them
}