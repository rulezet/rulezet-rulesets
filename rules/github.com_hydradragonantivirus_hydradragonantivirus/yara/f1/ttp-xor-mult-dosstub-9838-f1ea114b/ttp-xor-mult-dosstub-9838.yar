rule TTP_XOR_MULT_DOSStub_9838 {
  strings:
    $key_9838 = { cc 50 [2] b8 48 [2] ff 4a [2] b8 5b [2] f6 57 [2] fa 5d [2] ed 56 [2] f6 18 [2] cb }

  condition:
    any of them
}