rule TTP_XOR_MULT_DOSStub_b447 {
  strings:
    $key_b447 = { e0 2f [2] 94 37 [2] d3 35 [2] 94 24 [2] da 28 [2] d6 22 [2] c1 29 [2] da 67 [2] e7 }

  condition:
    any of them
}