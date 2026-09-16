rule TTP_XOR_MULT_DOSStub_9839 {
  strings:
    $key_9839 = { cc 51 [2] b8 49 [2] ff 4b [2] b8 5a [2] f6 56 [2] fa 5c [2] ed 57 [2] f6 19 [2] cb }

  condition:
    any of them
}