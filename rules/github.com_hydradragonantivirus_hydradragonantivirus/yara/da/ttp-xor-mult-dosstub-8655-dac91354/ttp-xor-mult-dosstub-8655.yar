rule TTP_XOR_MULT_DOSStub_8655 {
  strings:
    $key_8655 = { d2 3d [2] a6 25 [2] e1 27 [2] a6 36 [2] e8 3a [2] e4 30 [2] f3 3b [2] e8 75 [2] d5 }

  condition:
    any of them
}