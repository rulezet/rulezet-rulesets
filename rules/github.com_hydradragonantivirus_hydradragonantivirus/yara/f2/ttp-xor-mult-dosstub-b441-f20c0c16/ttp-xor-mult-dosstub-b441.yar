rule TTP_XOR_MULT_DOSStub_b441 {
  strings:
    $key_b441 = { e0 29 [2] 94 31 [2] d3 33 [2] 94 22 [2] da 2e [2] d6 24 [2] c1 2f [2] da 61 [2] e7 }

  condition:
    any of them
}