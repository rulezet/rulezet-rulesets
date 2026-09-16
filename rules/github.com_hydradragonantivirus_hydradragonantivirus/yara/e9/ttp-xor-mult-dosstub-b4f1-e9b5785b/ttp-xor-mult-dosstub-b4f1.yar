rule TTP_XOR_MULT_DOSStub_b4f1 {
  strings:
    $key_b4f1 = { e0 99 [2] 94 81 [2] d3 83 [2] 94 92 [2] da 9e [2] d6 94 [2] c1 9f [2] da d1 [2] e7 }

  condition:
    any of them
}