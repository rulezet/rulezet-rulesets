rule TTP_XOR_MULT_DOSStub_9819 {
  strings:
    $key_9819 = { cc 71 [2] b8 69 [2] ff 6b [2] b8 7a [2] f6 76 [2] fa 7c [2] ed 77 [2] f6 39 [2] cb }

  condition:
    any of them
}