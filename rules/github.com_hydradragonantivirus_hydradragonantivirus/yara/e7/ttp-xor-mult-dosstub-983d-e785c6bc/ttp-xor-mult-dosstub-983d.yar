rule TTP_XOR_MULT_DOSStub_983d {
  strings:
    $key_983d = { cc 55 [2] b8 4d [2] ff 4f [2] b8 5e [2] f6 52 [2] fa 58 [2] ed 53 [2] f6 1d [2] cb }

  condition:
    any of them
}