rule TTP_XOR_MULT_DOSStub_98e3 {
  strings:
    $key_98e3 = { cc 8b [2] b8 93 [2] ff 91 [2] b8 80 [2] f6 8c [2] fa 86 [2] ed 8d [2] f6 c3 [2] cb }

  condition:
    any of them
}