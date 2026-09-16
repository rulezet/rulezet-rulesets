rule TTP_XOR_MULT_DOSStub_9065 {
  strings:
    $key_9065 = { c4 0d [2] b0 15 [2] f7 17 [2] b0 06 [2] fe 0a [2] f2 00 [2] e5 0b [2] fe 45 [2] c3 }

  condition:
    any of them
}