rule TTP_XOR_MULT_DOSStub_9540 {
  strings:
    $key_9540 = { c1 28 [2] b5 30 [2] f2 32 [2] b5 23 [2] fb 2f [2] f7 25 [2] e0 2e [2] fb 60 [2] c6 }

  condition:
    any of them
}