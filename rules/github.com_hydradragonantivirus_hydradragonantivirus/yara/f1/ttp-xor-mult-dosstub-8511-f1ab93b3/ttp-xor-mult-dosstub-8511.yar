rule TTP_XOR_MULT_DOSStub_8511 {
  strings:
    $key_8511 = { d1 79 [2] a5 61 [2] e2 63 [2] a5 72 [2] eb 7e [2] e7 74 [2] f0 7f [2] eb 31 [2] d6 }

  condition:
    any of them
}