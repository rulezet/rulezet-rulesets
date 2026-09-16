rule TTP_XOR_MULT_DOSStub_9877 {
  strings:
    $key_9877 = { cc 1f [2] b8 07 [2] ff 05 [2] b8 14 [2] f6 18 [2] fa 12 [2] ed 19 [2] f6 57 [2] cb }

  condition:
    any of them
}