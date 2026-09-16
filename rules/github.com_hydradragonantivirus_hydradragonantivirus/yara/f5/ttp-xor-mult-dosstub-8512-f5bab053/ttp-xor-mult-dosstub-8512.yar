rule TTP_XOR_MULT_DOSStub_8512 {
  strings:
    $key_8512 = { d1 7a [2] a5 62 [2] e2 60 [2] a5 71 [2] eb 7d [2] e7 77 [2] f0 7c [2] eb 32 [2] d6 }

  condition:
    any of them
}