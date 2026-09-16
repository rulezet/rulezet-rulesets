rule TTP_XOR_MULT_DOSStub_98b9 {
  strings:
    $key_98b9 = { cc d1 [2] b8 c9 [2] ff cb [2] b8 da [2] f6 d6 [2] fa dc [2] ed d7 [2] f6 99 [2] cb }

  condition:
    any of them
}