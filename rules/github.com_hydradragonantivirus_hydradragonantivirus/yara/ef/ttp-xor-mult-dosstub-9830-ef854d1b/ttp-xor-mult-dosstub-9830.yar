rule TTP_XOR_MULT_DOSStub_9830 {
  strings:
    $key_9830 = { cc 58 [2] b8 40 [2] ff 42 [2] b8 53 [2] f6 5f [2] fa 55 [2] ed 5e [2] f6 10 [2] cb }

  condition:
    any of them
}