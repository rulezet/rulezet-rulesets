rule TTP_XOR_MULT_DOSStub_9552 {
  strings:
    $key_9552 = { c1 3a [2] b5 22 [2] f2 20 [2] b5 31 [2] fb 3d [2] f7 37 [2] e0 3c [2] fb 72 [2] c6 }

  condition:
    any of them
}