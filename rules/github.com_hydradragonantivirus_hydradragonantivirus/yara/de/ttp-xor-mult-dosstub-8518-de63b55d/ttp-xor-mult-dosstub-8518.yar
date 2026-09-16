rule TTP_XOR_MULT_DOSStub_8518 {
  strings:
    $key_8518 = { d1 70 [2] a5 68 [2] e2 6a [2] a5 7b [2] eb 77 [2] e7 7d [2] f0 76 [2] eb 38 [2] d6 }

  condition:
    any of them
}