rule TTP_XOR_MULT_DOSStub_983b {
  strings:
    $key_983b = { cc 53 [2] b8 4b [2] ff 49 [2] b8 58 [2] f6 54 [2] fa 5e [2] ed 55 [2] f6 1b [2] cb }

  condition:
    any of them
}