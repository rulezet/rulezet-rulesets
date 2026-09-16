rule TTP_XOR_MULT_DOSStub_98fa {
  strings:
    $key_98fa = { cc 92 [2] b8 8a [2] ff 88 [2] b8 99 [2] f6 95 [2] fa 9f [2] ed 94 [2] f6 da [2] cb }

  condition:
    any of them
}