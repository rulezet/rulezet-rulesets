rule TTP_XOR_MULT_DOSStub_b405 {
  strings:
    $key_b405 = { e0 6d [2] 94 75 [2] d3 77 [2] 94 66 [2] da 6a [2] d6 60 [2] c1 6b [2] da 25 [2] e7 }

  condition:
    any of them
}