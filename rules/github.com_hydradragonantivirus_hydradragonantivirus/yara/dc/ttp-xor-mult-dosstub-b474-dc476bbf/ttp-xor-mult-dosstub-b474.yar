rule TTP_XOR_MULT_DOSStub_b474 {
  strings:
    $key_b474 = { e0 1c [2] 94 04 [2] d3 06 [2] 94 17 [2] da 1b [2] d6 11 [2] c1 1a [2] da 54 [2] e7 }

  condition:
    any of them
}