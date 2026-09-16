rule TTP_XOR_MULT_DOSStub_96a8 {
  strings:
    $key_96a8 = { c2 c0 [2] b6 d8 [2] f1 da [2] b6 cb [2] f8 c7 [2] f4 cd [2] e3 c6 [2] f8 88 [2] c5 }

  condition:
    any of them
}