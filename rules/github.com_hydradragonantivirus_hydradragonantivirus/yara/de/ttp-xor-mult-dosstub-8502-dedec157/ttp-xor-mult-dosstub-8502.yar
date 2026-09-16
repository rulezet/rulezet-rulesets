rule TTP_XOR_MULT_DOSStub_8502 {
  strings:
    $key_8502 = { d1 6a [2] a5 72 [2] e2 70 [2] a5 61 [2] eb 6d [2] e7 67 [2] f0 6c [2] eb 22 [2] d6 }

  condition:
    any of them
}