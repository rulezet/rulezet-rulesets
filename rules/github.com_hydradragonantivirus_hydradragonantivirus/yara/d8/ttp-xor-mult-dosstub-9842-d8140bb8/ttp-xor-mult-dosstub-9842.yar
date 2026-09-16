rule TTP_XOR_MULT_DOSStub_9842 {
  strings:
    $key_9842 = { cc 2a [2] b8 32 [2] ff 30 [2] b8 21 [2] f6 2d [2] fa 27 [2] ed 2c [2] f6 62 [2] cb }

  condition:
    any of them
}