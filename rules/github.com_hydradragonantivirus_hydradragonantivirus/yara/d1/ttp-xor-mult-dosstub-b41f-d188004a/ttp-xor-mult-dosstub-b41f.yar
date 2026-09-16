rule TTP_XOR_MULT_DOSStub_b41f {
  strings:
    $key_b41f = { e0 77 [2] 94 6f [2] d3 6d [2] 94 7c [2] da 70 [2] d6 7a [2] c1 71 [2] da 3f [2] e7 }

  condition:
    any of them
}