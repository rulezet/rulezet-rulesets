rule TTP_XOR_MULT_DOSStub_b464 {
  strings:
    $key_b464 = { e0 0c [2] 94 14 [2] d3 16 [2] 94 07 [2] da 0b [2] d6 01 [2] c1 0a [2] da 44 [2] e7 }

  condition:
    any of them
}