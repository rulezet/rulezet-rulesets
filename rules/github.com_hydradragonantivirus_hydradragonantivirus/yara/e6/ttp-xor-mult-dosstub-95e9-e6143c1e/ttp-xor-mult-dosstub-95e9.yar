rule TTP_XOR_MULT_DOSStub_95e9 {
  strings:
    $key_95e9 = { c1 81 [2] b5 99 [2] f2 9b [2] b5 8a [2] fb 86 [2] f7 8c [2] e0 87 [2] fb c9 [2] c6 }

  condition:
    any of them
}