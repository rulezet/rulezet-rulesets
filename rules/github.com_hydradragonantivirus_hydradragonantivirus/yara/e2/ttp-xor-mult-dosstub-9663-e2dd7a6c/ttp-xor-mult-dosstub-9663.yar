rule TTP_XOR_MULT_DOSStub_9663 {
  strings:
    $key_9663 = { c2 0b [2] b6 13 [2] f1 11 [2] b6 00 [2] f8 0c [2] f4 06 [2] e3 0d [2] f8 43 [2] c5 }

  condition:
    any of them
}