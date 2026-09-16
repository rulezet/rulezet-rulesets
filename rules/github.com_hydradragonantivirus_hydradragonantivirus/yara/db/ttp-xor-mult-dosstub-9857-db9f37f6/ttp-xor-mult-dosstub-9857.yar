rule TTP_XOR_MULT_DOSStub_9857 {
  strings:
    $key_9857 = { cc 3f [2] b8 27 [2] ff 25 [2] b8 34 [2] f6 38 [2] fa 32 [2] ed 39 [2] f6 77 [2] cb }

  condition:
    any of them
}