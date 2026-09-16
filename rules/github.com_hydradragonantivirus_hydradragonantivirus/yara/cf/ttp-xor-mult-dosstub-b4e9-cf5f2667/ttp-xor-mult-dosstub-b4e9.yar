rule TTP_XOR_MULT_DOSStub_b4e9 {
  strings:
    $key_b4e9 = { e0 81 [2] 94 99 [2] d3 9b [2] 94 8a [2] da 86 [2] d6 8c [2] c1 87 [2] da c9 [2] e7 }

  condition:
    any of them
}