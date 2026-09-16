rule TTP_XOR_MULT_DOSStub_8537 {
  strings:
    $key_8537 = { d1 5f [2] a5 47 [2] e2 45 [2] a5 54 [2] eb 58 [2] e7 52 [2] f0 59 [2] eb 17 [2] d6 }

  condition:
    any of them
}