rule TTP_XOR_MULT_DOSStub_95f5 {
  strings:
    $key_95f5 = { c1 9d [2] b5 85 [2] f2 87 [2] b5 96 [2] fb 9a [2] f7 90 [2] e0 9b [2] fb d5 [2] c6 }

  condition:
    any of them
}