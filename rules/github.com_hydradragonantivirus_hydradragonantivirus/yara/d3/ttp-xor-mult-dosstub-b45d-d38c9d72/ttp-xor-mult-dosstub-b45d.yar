rule TTP_XOR_MULT_DOSStub_b45d {
  strings:
    $key_b45d = { e0 35 [2] 94 2d [2] d3 2f [2] 94 3e [2] da 32 [2] d6 38 [2] c1 33 [2] da 7d [2] e7 }

  condition:
    any of them
}