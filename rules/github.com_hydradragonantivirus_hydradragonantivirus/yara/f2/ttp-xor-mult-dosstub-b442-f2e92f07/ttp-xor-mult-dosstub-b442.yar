rule TTP_XOR_MULT_DOSStub_b442 {
  strings:
    $key_b442 = { e0 2a [2] 94 32 [2] d3 30 [2] 94 21 [2] da 2d [2] d6 27 [2] c1 2c [2] da 62 [2] e7 }

  condition:
    any of them
}