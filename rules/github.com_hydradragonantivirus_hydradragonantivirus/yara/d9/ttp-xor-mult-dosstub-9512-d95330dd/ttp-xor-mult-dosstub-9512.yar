rule TTP_XOR_MULT_DOSStub_9512 {
  strings:
    $key_9512 = { c1 7a [2] b5 62 [2] f2 60 [2] b5 71 [2] fb 7d [2] f7 77 [2] e0 7c [2] fb 32 [2] c6 }

  condition:
    any of them
}