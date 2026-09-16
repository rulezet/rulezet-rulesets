rule TTP_XOR_MULT_DOSStub_b43d {
  strings:
    $key_b43d = { e0 55 [2] 94 4d [2] d3 4f [2] 94 5e [2] da 52 [2] d6 58 [2] c1 53 [2] da 1d [2] e7 }

  condition:
    any of them
}