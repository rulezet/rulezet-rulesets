rule TTP_XOR_MULT_DOSStub_9765 {
  strings:
    $key_9765 = { c3 0d [2] b7 15 [2] f0 17 [2] b7 06 [2] f9 0a [2] f5 00 [2] e2 0b [2] f9 45 [2] c4 }

  condition:
    any of them
}