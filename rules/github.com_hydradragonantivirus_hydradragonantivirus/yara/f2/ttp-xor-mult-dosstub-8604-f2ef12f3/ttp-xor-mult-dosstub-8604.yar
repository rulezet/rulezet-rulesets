rule TTP_XOR_MULT_DOSStub_8604 {
  strings:
    $key_8604 = { d2 6c [2] a6 74 [2] e1 76 [2] a6 67 [2] e8 6b [2] e4 61 [2] f3 6a [2] e8 24 [2] d5 }

  condition:
    any of them
}