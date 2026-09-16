rule TTP_XOR_MULT_DOSStub_9801 {
  strings:
    $key_9801 = { cc 69 [2] b8 71 [2] ff 73 [2] b8 62 [2] f6 6e [2] fa 64 [2] ed 6f [2] f6 21 [2] cb }

  condition:
    any of them
}