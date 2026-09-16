rule TTP_XOR_MULT_DOSStub_8507 {
  strings:
    $key_8507 = { d1 6f [2] a5 77 [2] e2 75 [2] a5 64 [2] eb 68 [2] e7 62 [2] f0 69 [2] eb 27 [2] d6 }

  condition:
    any of them
}