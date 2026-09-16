rule TTP_XOR_MULT_DOSStub_985c {
  strings:
    $key_985c = { cc 34 [2] b8 2c [2] ff 2e [2] b8 3f [2] f6 33 [2] fa 39 [2] ed 32 [2] f6 7c [2] cb }

  condition:
    any of them
}