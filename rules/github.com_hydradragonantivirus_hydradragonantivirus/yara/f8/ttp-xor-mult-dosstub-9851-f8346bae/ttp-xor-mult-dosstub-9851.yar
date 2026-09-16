rule TTP_XOR_MULT_DOSStub_9851 {
  strings:
    $key_9851 = { cc 39 [2] b8 21 [2] ff 23 [2] b8 32 [2] f6 3e [2] fa 34 [2] ed 3f [2] f6 71 [2] cb }

  condition:
    any of them
}