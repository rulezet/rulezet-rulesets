rule TTP_XOR_MULT_DOSStub_9668 {
  strings:
    $key_9668 = { c2 00 [2] b6 18 [2] f1 1a [2] b6 0b [2] f8 07 [2] f4 0d [2] e3 06 [2] f8 48 [2] c5 }

  condition:
    any of them
}