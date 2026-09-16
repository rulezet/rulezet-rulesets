rule TTP_XOR_MULT_DOSStub_b469 {
  strings:
    $key_b469 = { e0 01 [2] 94 19 [2] d3 1b [2] 94 0a [2] da 06 [2] d6 0c [2] c1 07 [2] da 49 [2] e7 }

  condition:
    any of them
}