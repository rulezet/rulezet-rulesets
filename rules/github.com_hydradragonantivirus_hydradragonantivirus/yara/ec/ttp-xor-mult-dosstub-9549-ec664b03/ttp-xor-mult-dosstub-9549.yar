rule TTP_XOR_MULT_DOSStub_9549 {
  strings:
    $key_9549 = { c1 21 [2] b5 39 [2] f2 3b [2] b5 2a [2] fb 26 [2] f7 2c [2] e0 27 [2] fb 69 [2] c6 }

  condition:
    any of them
}