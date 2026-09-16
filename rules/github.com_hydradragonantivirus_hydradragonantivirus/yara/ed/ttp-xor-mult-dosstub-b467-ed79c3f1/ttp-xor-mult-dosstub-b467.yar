rule TTP_XOR_MULT_DOSStub_b467 {
  strings:
    $key_b467 = { e0 0f [2] 94 17 [2] d3 15 [2] 94 04 [2] da 08 [2] d6 02 [2] c1 09 [2] da 47 [2] e7 }

  condition:
    any of them
}