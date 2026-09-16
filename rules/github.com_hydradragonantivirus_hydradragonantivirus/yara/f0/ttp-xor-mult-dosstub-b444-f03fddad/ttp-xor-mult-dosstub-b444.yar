rule TTP_XOR_MULT_DOSStub_b444 {
  strings:
    $key_b444 = { e0 2c [2] 94 34 [2] d3 36 [2] 94 27 [2] da 2b [2] d6 21 [2] c1 2a [2] da 64 [2] e7 }

  condition:
    any of them
}