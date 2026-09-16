rule TTP_XOR_MULT_DOSStub_8654 {
  strings:
    $key_8654 = { d2 3c [2] a6 24 [2] e1 26 [2] a6 37 [2] e8 3b [2] e4 31 [2] f3 3a [2] e8 74 [2] d5 }

  condition:
    any of them
}