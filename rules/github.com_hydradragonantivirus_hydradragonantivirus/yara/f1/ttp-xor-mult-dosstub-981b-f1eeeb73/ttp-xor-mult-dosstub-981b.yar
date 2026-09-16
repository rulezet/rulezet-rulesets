rule TTP_XOR_MULT_DOSStub_981b {
  strings:
    $key_981b = { cc 73 [2] b8 6b [2] ff 69 [2] b8 78 [2] f6 74 [2] fa 7e [2] ed 75 [2] f6 3b [2] cb }

  condition:
    any of them
}