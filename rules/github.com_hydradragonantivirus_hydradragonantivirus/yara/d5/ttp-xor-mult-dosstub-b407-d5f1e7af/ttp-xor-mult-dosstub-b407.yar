rule TTP_XOR_MULT_DOSStub_b407 {
  strings:
    $key_b407 = { e0 6f [2] 94 77 [2] d3 75 [2] 94 64 [2] da 68 [2] d6 62 [2] c1 69 [2] da 27 [2] e7 }

  condition:
    any of them
}