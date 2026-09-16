rule TTP_XOR_MULT_DOSStub_9659 {
  strings:
    $key_9659 = { c2 31 [2] b6 29 [2] f1 2b [2] b6 3a [2] f8 36 [2] f4 3c [2] e3 37 [2] f8 79 [2] c5 }

  condition:
    any of them
}