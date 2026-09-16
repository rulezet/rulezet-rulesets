rule TTP_XOR_MULT_DOSStub_d8a6 {
  strings:
    $key_d8a6 = { 8c ce [2] f8 d6 [2] bf d4 [2] f8 c5 [2] b6 c9 [2] ba c3 [2] ad c8 [2] b6 86 [2] 8b }

  condition:
    any of them
}