rule TTP_XOR_MULT_DOSStub_8524 {
  strings:
    $key_8524 = { d1 4c [2] a5 54 [2] e2 56 [2] a5 47 [2] eb 4b [2] e7 41 [2] f0 4a [2] eb 04 [2] d6 }

  condition:
    any of them
}