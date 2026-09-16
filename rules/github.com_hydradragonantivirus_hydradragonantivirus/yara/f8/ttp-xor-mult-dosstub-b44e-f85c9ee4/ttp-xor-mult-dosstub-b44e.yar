rule TTP_XOR_MULT_DOSStub_b44e {
  strings:
    $key_b44e = { e0 26 [2] 94 3e [2] d3 3c [2] 94 2d [2] da 21 [2] d6 2b [2] c1 20 [2] da 6e [2] e7 }

  condition:
    any of them
}