rule TTP_XOR_MULT_DOSStub_9861 {
  strings:
    $key_9861 = { cc 09 [2] b8 11 [2] ff 13 [2] b8 02 [2] f6 0e [2] fa 04 [2] ed 0f [2] f6 41 [2] cb }

  condition:
    any of them
}