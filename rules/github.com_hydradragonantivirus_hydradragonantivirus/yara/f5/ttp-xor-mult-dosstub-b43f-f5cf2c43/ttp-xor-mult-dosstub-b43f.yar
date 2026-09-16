rule TTP_XOR_MULT_DOSStub_b43f {
  strings:
    $key_b43f = { e0 57 [2] 94 4f [2] d3 4d [2] 94 5c [2] da 50 [2] d6 5a [2] c1 51 [2] da 1f [2] e7 }

  condition:
    any of them
}