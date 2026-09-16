rule TTP_XOR_MULT_DOSStub_8649 {
  strings:
    $key_8649 = { d2 21 [2] a6 39 [2] e1 3b [2] a6 2a [2] e8 26 [2] e4 2c [2] f3 27 [2] e8 69 [2] d5 }

  condition:
    any of them
}