rule TTP_XOR_MULT_DOSStub_9869 {
  strings:
    $key_9869 = { cc 01 [2] b8 19 [2] ff 1b [2] b8 0a [2] f6 06 [2] fa 0c [2] ed 07 [2] f6 49 [2] cb }

  condition:
    any of them
}