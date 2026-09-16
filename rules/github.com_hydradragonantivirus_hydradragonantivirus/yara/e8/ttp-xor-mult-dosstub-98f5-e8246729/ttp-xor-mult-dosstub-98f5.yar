rule TTP_XOR_MULT_DOSStub_98f5 {
  strings:
    $key_98f5 = { cc 9d [2] b8 85 [2] ff 87 [2] b8 96 [2] f6 9a [2] fa 90 [2] ed 9b [2] f6 d5 [2] cb }

  condition:
    any of them
}