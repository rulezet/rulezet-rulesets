rule TTP_XOR_MULT_DOSStub_95e2 {
  strings:
    $key_95e2 = { c1 8a [2] b5 92 [2] f2 90 [2] b5 81 [2] fb 8d [2] f7 87 [2] e0 8c [2] fb c2 [2] c6 }

  condition:
    any of them
}