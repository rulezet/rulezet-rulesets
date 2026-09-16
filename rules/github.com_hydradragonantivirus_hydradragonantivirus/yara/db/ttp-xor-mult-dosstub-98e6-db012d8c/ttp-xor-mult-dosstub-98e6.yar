rule TTP_XOR_MULT_DOSStub_98e6 {
  strings:
    $key_98e6 = { cc 8e [2] b8 96 [2] ff 94 [2] b8 85 [2] f6 89 [2] fa 83 [2] ed 88 [2] f6 c6 [2] cb }

  condition:
    any of them
}