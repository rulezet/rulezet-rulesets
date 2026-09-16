rule TTP_XOR_MULT_DOSStub_8515 {
  strings:
    $key_8515 = { d1 7d [2] a5 65 [2] e2 67 [2] a5 76 [2] eb 7a [2] e7 70 [2] f0 7b [2] eb 35 [2] d6 }

  condition:
    any of them
}