rule TTP_XOR_MULT_DOSStub_98a7 {
  strings:
    $key_98a7 = { cc cf [2] b8 d7 [2] ff d5 [2] b8 c4 [2] f6 c8 [2] fa c2 [2] ed c9 [2] f6 87 [2] cb }

  condition:
    any of them
}