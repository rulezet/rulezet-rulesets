rule TTP_XOR_MULT_DOSStub_987c {
  strings:
    $key_987c = { cc 14 [2] b8 0c [2] ff 0e [2] b8 1f [2] f6 13 [2] fa 19 [2] ed 12 [2] f6 5c [2] cb }

  condition:
    any of them
}