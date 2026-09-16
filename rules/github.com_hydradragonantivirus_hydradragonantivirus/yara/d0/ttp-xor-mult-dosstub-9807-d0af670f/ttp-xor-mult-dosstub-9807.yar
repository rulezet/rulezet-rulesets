rule TTP_XOR_MULT_DOSStub_9807 {
  strings:
    $key_9807 = { cc 6f [2] b8 77 [2] ff 75 [2] b8 64 [2] f6 68 [2] fa 62 [2] ed 69 [2] f6 27 [2] cb }

  condition:
    any of them
}