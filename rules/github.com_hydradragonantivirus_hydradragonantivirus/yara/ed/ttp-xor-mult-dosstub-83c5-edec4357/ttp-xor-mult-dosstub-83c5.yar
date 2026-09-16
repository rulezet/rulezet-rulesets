rule TTP_XOR_MULT_DOSStub_83c5 {
  strings:
    $key_83c5 = { d7 ad [2] a3 b5 [2] e4 b7 [2] a3 a6 [2] ed aa [2] e1 a0 [2] f6 ab [2] ed e5 [2] d0 }

  condition:
    any of them
}