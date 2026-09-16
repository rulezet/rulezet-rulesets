rule TTP_XOR_MULT_DOSStub_9558 {
  strings:
    $key_9558 = { c1 30 [2] b5 28 [2] f2 2a [2] b5 3b [2] fb 37 [2] f7 3d [2] e0 36 [2] fb 78 [2] c6 }

  condition:
    any of them
}