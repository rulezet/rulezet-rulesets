rule TTP_XOR_MULT_DOSStub_8506 {
  strings:
    $key_8506 = { d1 6e [2] a5 76 [2] e2 74 [2] a5 65 [2] eb 69 [2] e7 63 [2] f0 68 [2] eb 26 [2] d6 }

  condition:
    any of them
}