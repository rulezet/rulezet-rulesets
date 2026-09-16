rule TTP_XOR_MULT_DOSStub_98d6 {
  strings:
    $key_98d6 = { cc be [2] b8 a6 [2] ff a4 [2] b8 b5 [2] f6 b9 [2] fa b3 [2] ed b8 [2] f6 f6 [2] cb }

  condition:
    any of them
}