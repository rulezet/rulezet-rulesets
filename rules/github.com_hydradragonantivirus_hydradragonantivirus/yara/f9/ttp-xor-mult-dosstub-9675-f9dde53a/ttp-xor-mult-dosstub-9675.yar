rule TTP_XOR_MULT_DOSStub_9675 {
  strings:
    $key_9675 = { c2 1d [2] b6 05 [2] f1 07 [2] b6 16 [2] f8 1a [2] f4 10 [2] e3 1b [2] f8 55 [2] c5 }

  condition:
    any of them
}