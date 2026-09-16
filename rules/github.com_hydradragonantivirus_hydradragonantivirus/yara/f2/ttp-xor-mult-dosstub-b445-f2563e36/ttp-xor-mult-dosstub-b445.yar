rule TTP_XOR_MULT_DOSStub_b445 {
  strings:
    $key_b445 = { e0 2d [2] 94 35 [2] d3 37 [2] 94 26 [2] da 2a [2] d6 20 [2] c1 2b [2] da 65 [2] e7 }

  condition:
    any of them
}