rule TTP_XOR_MULT_DOSStub_9823 {
  strings:
    $key_9823 = { cc 4b [2] b8 53 [2] ff 51 [2] b8 40 [2] f6 4c [2] fa 46 [2] ed 4d [2] f6 03 [2] cb }

  condition:
    any of them
}