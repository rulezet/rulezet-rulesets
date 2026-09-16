rule TTP_XOR_MULT_DOSStub_9679 {
  strings:
    $key_9679 = { c2 11 [2] b6 09 [2] f1 0b [2] b6 1a [2] f8 16 [2] f4 1c [2] e3 17 [2] f8 59 [2] c5 }

  condition:
    any of them
}