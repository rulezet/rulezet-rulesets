rule TTP_XOR_MULT_DOSStub_9516 {
  strings:
    $key_9516 = { c1 7e [2] b5 66 [2] f2 64 [2] b5 75 [2] fb 79 [2] f7 73 [2] e0 78 [2] fb 36 [2] c6 }

  condition:
    any of them
}