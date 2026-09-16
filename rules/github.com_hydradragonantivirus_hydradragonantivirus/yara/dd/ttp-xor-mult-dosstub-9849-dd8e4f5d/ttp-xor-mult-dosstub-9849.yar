rule TTP_XOR_MULT_DOSStub_9849 {
  strings:
    $key_9849 = { cc 21 [2] b8 39 [2] ff 3b [2] b8 2a [2] f6 26 [2] fa 2c [2] ed 27 [2] f6 69 [2] cb }

  condition:
    any of them
}