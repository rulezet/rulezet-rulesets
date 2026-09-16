rule TTP_XOR_MULT_DOSStub_8357 {
  strings:
    $key_8357 = { d7 3f [2] a3 27 [2] e4 25 [2] a3 34 [2] ed 38 [2] e1 32 [2] f6 39 [2] ed 77 [2] d0 }

  condition:
    any of them
}