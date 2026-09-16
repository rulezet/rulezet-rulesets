rule TTP_XOR_MULT_DOSStub_8652 {
  strings:
    $key_8652 = { d2 3a [2] a6 22 [2] e1 20 [2] a6 31 [2] e8 3d [2] e4 37 [2] f3 3c [2] e8 72 [2] d5 }

  condition:
    any of them
}