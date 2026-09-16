rule TTP_XOR_MULT_DOSStub_98d7 {
  strings:
    $key_98d7 = { cc bf [2] b8 a7 [2] ff a5 [2] b8 b4 [2] f6 b8 [2] fa b2 [2] ed b9 [2] f6 f7 [2] cb }

  condition:
    any of them
}