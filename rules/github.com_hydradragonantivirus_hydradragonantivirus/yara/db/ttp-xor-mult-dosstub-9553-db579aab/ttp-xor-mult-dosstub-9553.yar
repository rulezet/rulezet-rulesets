rule TTP_XOR_MULT_DOSStub_9553 {
  strings:
    $key_9553 = { c1 3b [2] b5 23 [2] f2 21 [2] b5 30 [2] fb 3c [2] f7 36 [2] e0 3d [2] fb 73 [2] c6 }

  condition:
    any of them
}