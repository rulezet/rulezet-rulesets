rule TTP_XOR_MULT_DOSStub_b408 {
  strings:
    $key_b408 = { e0 60 [2] 94 78 [2] d3 7a [2] 94 6b [2] da 67 [2] d6 6d [2] c1 66 [2] da 28 [2] e7 }

  condition:
    any of them
}