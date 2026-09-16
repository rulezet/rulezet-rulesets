rule TTP_XOR_MULT_DOSStub_b42d {
  strings:
    $key_b42d = { e0 45 [2] 94 5d [2] d3 5f [2] 94 4e [2] da 42 [2] d6 48 [2] c1 43 [2] da 0d [2] e7 }

  condition:
    any of them
}