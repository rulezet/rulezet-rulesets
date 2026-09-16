rule TTP_XOR_MULT_DOSStub_b44c {
  strings:
    $key_b44c = { e0 24 [2] 94 3c [2] d3 3e [2] 94 2f [2] da 23 [2] d6 29 [2] c1 22 [2] da 6c [2] e7 }

  condition:
    any of them
}