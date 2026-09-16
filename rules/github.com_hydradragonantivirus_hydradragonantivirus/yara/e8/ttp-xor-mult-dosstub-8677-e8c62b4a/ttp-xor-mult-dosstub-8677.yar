rule TTP_XOR_MULT_DOSStub_8677 {
  strings:
    $key_8677 = { d2 1f [2] a6 07 [2] e1 05 [2] a6 14 [2] e8 18 [2] e4 12 [2] f3 19 [2] e8 57 [2] d5 }

  condition:
    any of them
}