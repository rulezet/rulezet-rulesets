rule TTP_XOR_MULT_DOSStub_b433 {
  strings:
    $key_b433 = { e0 5b [2] 94 43 [2] d3 41 [2] 94 50 [2] da 5c [2] d6 56 [2] c1 5d [2] da 13 [2] e7 }

  condition:
    any of them
}