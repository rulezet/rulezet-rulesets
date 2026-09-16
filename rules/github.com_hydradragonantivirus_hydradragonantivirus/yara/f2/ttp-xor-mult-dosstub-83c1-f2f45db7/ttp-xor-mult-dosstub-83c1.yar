rule TTP_XOR_MULT_DOSStub_83c1 {
  strings:
    $key_83c1 = { d7 a9 [2] a3 b1 [2] e4 b3 [2] a3 a2 [2] ed ae [2] e1 a4 [2] f6 af [2] ed e1 [2] d0 }

  condition:
    any of them
}