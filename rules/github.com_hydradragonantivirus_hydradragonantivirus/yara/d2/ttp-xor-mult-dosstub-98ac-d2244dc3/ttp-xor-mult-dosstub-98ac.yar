rule TTP_XOR_MULT_DOSStub_98ac {
  strings:
    $key_98ac = { cc c4 [2] b8 dc [2] ff de [2] b8 cf [2] f6 c3 [2] fa c9 [2] ed c2 [2] f6 8c [2] cb }

  condition:
    any of them
}