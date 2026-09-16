rule TTP_XOR_MULT_DOSStub_b472 {
  strings:
    $key_b472 = { e0 1a [2] 94 02 [2] d3 00 [2] 94 11 [2] da 1d [2] d6 17 [2] c1 1c [2] da 52 [2] e7 }

  condition:
    any of them
}