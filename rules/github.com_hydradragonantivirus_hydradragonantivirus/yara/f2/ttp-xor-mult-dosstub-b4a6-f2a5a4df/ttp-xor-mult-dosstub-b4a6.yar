rule TTP_XOR_MULT_DOSStub_b4a6 {
  strings:
    $key_b4a6 = { e0 ce [2] 94 d6 [2] d3 d4 [2] 94 c5 [2] da c9 [2] d6 c3 [2] c1 c8 [2] da 86 [2] e7 }

  condition:
    any of them
}