rule TTP_XOR_MULT_DOSStub_b410 {
  strings:
    $key_b410 = { e0 78 [2] 94 60 [2] d3 62 [2] 94 73 [2] da 7f [2] d6 75 [2] c1 7e [2] da 30 [2] e7 }

  condition:
    any of them
}