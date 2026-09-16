rule TTP_XOR_MULT_DOSStub_9873 {
  strings:
    $key_9873 = { cc 1b [2] b8 03 [2] ff 01 [2] b8 10 [2] f6 1c [2] fa 16 [2] ed 1d [2] f6 53 [2] cb }

  condition:
    any of them
}