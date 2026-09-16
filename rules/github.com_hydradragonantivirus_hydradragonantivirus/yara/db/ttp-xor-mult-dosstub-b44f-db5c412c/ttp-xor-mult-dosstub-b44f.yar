rule TTP_XOR_MULT_DOSStub_b44f {
  strings:
    $key_b44f = { e0 27 [2] 94 3f [2] d3 3d [2] 94 2c [2] da 20 [2] d6 2a [2] c1 21 [2] da 6f [2] e7 }

  condition:
    any of them
}