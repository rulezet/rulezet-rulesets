rule TTP_XOR_MULT_DOSStub_8644 {
  strings:
    $key_8644 = { d2 2c [2] a6 34 [2] e1 36 [2] a6 27 [2] e8 2b [2] e4 21 [2] f3 2a [2] e8 64 [2] d5 }

  condition:
    any of them
}