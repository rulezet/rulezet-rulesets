rule TTP_XOR_MULT_DOSStub_9863 {
  strings:
    $key_9863 = { cc 0b [2] b8 13 [2] ff 11 [2] b8 00 [2] f6 0c [2] fa 06 [2] ed 0d [2] f6 43 [2] cb }

  condition:
    any of them
}