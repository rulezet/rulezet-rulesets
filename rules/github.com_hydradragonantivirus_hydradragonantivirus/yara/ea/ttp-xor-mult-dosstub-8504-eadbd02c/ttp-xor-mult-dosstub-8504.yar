rule TTP_XOR_MULT_DOSStub_8504 {
  strings:
    $key_8504 = { d1 6c [2] a5 74 [2] e2 76 [2] a5 67 [2] eb 6b [2] e7 61 [2] f0 6a [2] eb 24 [2] d6 }

  condition:
    any of them
}