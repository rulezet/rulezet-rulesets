rule TTP_XOR_MULT_DOSStub_9008 {
  strings:
    $key_9008 = { c4 60 [2] b0 78 [2] f7 7a [2] b0 6b [2] fe 67 [2] f2 6d [2] e5 66 [2] fe 28 [2] c3 }

  condition:
    any of them
}