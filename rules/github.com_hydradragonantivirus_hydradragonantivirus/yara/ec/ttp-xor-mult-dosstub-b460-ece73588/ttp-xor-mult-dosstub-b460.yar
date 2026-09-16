rule TTP_XOR_MULT_DOSStub_b460 {
  strings:
    $key_b460 = { e0 08 [2] 94 10 [2] d3 12 [2] 94 03 [2] da 0f [2] d6 05 [2] c1 0e [2] da 40 [2] e7 }

  condition:
    any of them
}