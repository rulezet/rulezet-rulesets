rule TTP_XOR_MULT_DOSStub_b048 {
  strings:
    $key_b048 = { e4 20 [2] 90 38 [2] d7 3a [2] 90 2b [2] de 27 [2] d2 2d [2] c5 26 [2] de 68 [2] e3 }

  condition:
    any of them
}