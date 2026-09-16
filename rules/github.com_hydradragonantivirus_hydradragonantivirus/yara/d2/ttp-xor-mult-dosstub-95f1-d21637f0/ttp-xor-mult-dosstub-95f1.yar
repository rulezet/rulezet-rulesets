rule TTP_XOR_MULT_DOSStub_95f1 {
  strings:
    $key_95f1 = { c1 99 [2] b5 81 [2] f2 83 [2] b5 92 [2] fb 9e [2] f7 94 [2] e0 9f [2] fb d1 [2] c6 }

  condition:
    any of them
}