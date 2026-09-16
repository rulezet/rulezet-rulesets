rule TTP_XOR_MULT_DOSStub_9874 {
  strings:
    $key_9874 = { cc 1c [2] b8 04 [2] ff 06 [2] b8 17 [2] f6 1b [2] fa 11 [2] ed 1a [2] f6 54 [2] cb }

  condition:
    any of them
}