rule TTP_XOR_MULT_DOSStub_9643 {
  strings:
    $key_9643 = { c2 2b [2] b6 33 [2] f1 31 [2] b6 20 [2] f8 2c [2] f4 26 [2] e3 2d [2] f8 63 [2] c5 }

  condition:
    any of them
}