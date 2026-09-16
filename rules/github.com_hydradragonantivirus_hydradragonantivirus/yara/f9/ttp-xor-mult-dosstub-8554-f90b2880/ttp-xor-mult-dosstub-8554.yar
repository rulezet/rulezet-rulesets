rule TTP_XOR_MULT_DOSStub_8554 {
  strings:
    $key_8554 = { d1 3c [2] a5 24 [2] e2 26 [2] a5 37 [2] eb 3b [2] e7 31 [2] f0 3a [2] eb 74 [2] d6 }

  condition:
    any of them
}