rule TTP_XOR_MULT_DOSStub_96d9 {
  strings:
    $key_96d9 = { c2 b1 [2] b6 a9 [2] f1 ab [2] b6 ba [2] f8 b6 [2] f4 bc [2] e3 b7 [2] f8 f9 [2] c5 }

  condition:
    any of them
}