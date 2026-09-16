rule TTP_XOR_MULT_DOSStub_8540 {
  strings:
    $key_8540 = { d1 28 [2] a5 30 [2] e2 32 [2] a5 23 [2] eb 2f [2] e7 25 [2] f0 2e [2] eb 60 [2] d6 }

  condition:
    any of them
}