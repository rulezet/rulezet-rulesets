rule TTP_XOR_MULT_DOSStub_95f6 {
  strings:
    $key_95f6 = { c1 9e [2] b5 86 [2] f2 84 [2] b5 95 [2] fb 99 [2] f7 93 [2] e0 98 [2] fb d6 [2] c6 }

  condition:
    any of them
}