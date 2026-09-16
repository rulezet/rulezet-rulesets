rule TTP_XOR_MULT_DOSStub_b461 {
  strings:
    $key_b461 = { e0 09 [2] 94 11 [2] d3 13 [2] 94 02 [2] da 0e [2] d6 04 [2] c1 0f [2] da 41 [2] e7 }

  condition:
    any of them
}