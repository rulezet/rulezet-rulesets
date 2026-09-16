rule TTP_XOR_MULT_DOSStub_9715 {
  strings:
    $key_9715 = { c3 7d [2] b7 65 [2] f0 67 [2] b7 76 [2] f9 7a [2] f5 70 [2] e2 7b [2] f9 35 [2] c4 }

  condition:
    any of them
}