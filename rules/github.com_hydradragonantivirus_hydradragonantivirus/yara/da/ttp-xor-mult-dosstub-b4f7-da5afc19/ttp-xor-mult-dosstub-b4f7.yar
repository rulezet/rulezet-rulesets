rule TTP_XOR_MULT_DOSStub_b4f7 {
  strings:
    $key_b4f7 = { e0 9f [2] 94 87 [2] d3 85 [2] 94 94 [2] da 98 [2] d6 92 [2] c1 99 [2] da d7 [2] e7 }

  condition:
    any of them
}