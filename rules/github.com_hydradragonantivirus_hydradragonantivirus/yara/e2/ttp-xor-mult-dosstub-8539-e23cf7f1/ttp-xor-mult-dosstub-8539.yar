rule TTP_XOR_MULT_DOSStub_8539 {
  strings:
    $key_8539 = { d1 51 [2] a5 49 [2] e2 4b [2] a5 5a [2] eb 56 [2] e7 5c [2] f0 57 [2] eb 19 [2] d6 }

  condition:
    any of them
}