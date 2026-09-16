rule TTP_XOR_MULT_DOSStub_b470 {
  strings:
    $key_b470 = { e0 18 [2] 94 00 [2] d3 02 [2] 94 13 [2] da 1f [2] d6 15 [2] c1 1e [2] da 50 [2] e7 }

  condition:
    any of them
}