rule TTP_XOR_MULT_DOSStub_8508 {
  strings:
    $key_8508 = { d1 60 [2] a5 78 [2] e2 7a [2] a5 6b [2] eb 67 [2] e7 6d [2] f0 66 [2] eb 28 [2] d6 }

  condition:
    any of them
}