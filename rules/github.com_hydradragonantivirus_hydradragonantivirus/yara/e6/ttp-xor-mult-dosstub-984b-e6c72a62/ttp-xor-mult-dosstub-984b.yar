rule TTP_XOR_MULT_DOSStub_984b {
  strings:
    $key_984b = { cc 23 [2] b8 3b [2] ff 39 [2] b8 28 [2] f6 24 [2] fa 2e [2] ed 25 [2] f6 6b [2] cb }

  condition:
    any of them
}