rule TTP_XOR_MULT_DOSStub_b457 {
  strings:
    $key_b457 = { e0 3f [2] 94 27 [2] d3 25 [2] 94 34 [2] da 38 [2] d6 32 [2] c1 39 [2] da 77 [2] e7 }

  condition:
    any of them
}