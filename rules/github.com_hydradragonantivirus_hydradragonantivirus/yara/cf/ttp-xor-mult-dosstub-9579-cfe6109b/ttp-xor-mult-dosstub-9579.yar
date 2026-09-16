rule TTP_XOR_MULT_DOSStub_9579 {
  strings:
    $key_9579 = { c1 11 [2] b5 09 [2] f2 0b [2] b5 1a [2] fb 16 [2] f7 1c [2] e0 17 [2] fb 59 [2] c6 }

  condition:
    any of them
}