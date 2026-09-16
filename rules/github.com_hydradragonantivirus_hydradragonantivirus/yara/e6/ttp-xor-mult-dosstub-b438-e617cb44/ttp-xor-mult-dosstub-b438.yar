rule TTP_XOR_MULT_DOSStub_b438 {
  strings:
    $key_b438 = { e0 50 [2] 94 48 [2] d3 4a [2] 94 5b [2] da 57 [2] d6 5d [2] c1 56 [2] da 18 [2] e7 }

  condition:
    any of them
}