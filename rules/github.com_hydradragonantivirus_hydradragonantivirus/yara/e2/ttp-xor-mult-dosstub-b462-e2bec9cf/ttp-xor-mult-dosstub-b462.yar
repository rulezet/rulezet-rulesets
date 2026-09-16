rule TTP_XOR_MULT_DOSStub_b462 {
  strings:
    $key_b462 = { e0 0a [2] 94 12 [2] d3 10 [2] 94 01 [2] da 0d [2] d6 07 [2] c1 0c [2] da 42 [2] e7 }

  condition:
    any of them
}