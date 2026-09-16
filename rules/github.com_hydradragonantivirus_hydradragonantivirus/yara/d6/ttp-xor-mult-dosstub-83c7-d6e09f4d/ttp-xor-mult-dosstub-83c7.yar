rule TTP_XOR_MULT_DOSStub_83c7 {
  strings:
    $key_83c7 = { d7 af [2] a3 b7 [2] e4 b5 [2] a3 a4 [2] ed a8 [2] e1 a2 [2] f6 a9 [2] ed e7 [2] d0 }

  condition:
    any of them
}