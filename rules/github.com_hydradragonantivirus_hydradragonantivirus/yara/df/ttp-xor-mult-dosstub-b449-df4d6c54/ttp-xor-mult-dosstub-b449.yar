rule TTP_XOR_MULT_DOSStub_b449 {
  strings:
    $key_b449 = { e0 21 [2] 94 39 [2] d3 3b [2] 94 2a [2] da 26 [2] d6 2c [2] c1 27 [2] da 69 [2] e7 }

  condition:
    any of them
}