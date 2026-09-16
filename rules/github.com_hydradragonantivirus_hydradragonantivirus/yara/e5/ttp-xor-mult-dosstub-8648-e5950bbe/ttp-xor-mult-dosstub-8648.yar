rule TTP_XOR_MULT_DOSStub_8648 {
  strings:
    $key_8648 = { d2 20 [2] a6 38 [2] e1 3a [2] a6 2b [2] e8 27 [2] e4 2d [2] f3 26 [2] e8 68 [2] d5 }

  condition:
    any of them
}