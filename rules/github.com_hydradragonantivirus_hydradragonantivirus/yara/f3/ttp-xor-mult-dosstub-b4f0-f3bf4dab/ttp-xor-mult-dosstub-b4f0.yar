rule TTP_XOR_MULT_DOSStub_b4f0 {
  strings:
    $key_b4f0 = { e0 98 [2] 94 80 [2] d3 82 [2] 94 93 [2] da 9f [2] d6 95 [2] c1 9e [2] da d0 [2] e7 }

  condition:
    any of them
}