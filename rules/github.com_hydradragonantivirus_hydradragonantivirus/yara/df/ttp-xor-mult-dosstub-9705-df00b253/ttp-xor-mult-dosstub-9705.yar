rule TTP_XOR_MULT_DOSStub_9705 {
  strings:
    $key_9705 = { c3 6d [2] b7 75 [2] f0 77 [2] b7 66 [2] f9 6a [2] f5 60 [2] e2 6b [2] f9 25 [2] c4 }

  condition:
    any of them
}