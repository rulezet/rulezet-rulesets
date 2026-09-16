rule TTP_XOR_MULT_DOSStub_b454 {
  strings:
    $key_b454 = { e0 3c [2] 94 24 [2] d3 26 [2] 94 37 [2] da 3b [2] d6 31 [2] c1 3a [2] da 74 [2] e7 }

  condition:
    any of them
}