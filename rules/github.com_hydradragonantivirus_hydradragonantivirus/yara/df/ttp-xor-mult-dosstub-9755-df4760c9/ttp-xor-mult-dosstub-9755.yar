rule TTP_XOR_MULT_DOSStub_9755 {
  strings:
    $key_9755 = { c3 3d [2] b7 25 [2] f0 27 [2] b7 36 [2] f9 3a [2] f5 30 [2] e2 3b [2] f9 75 [2] c4 }

  condition:
    any of them
}