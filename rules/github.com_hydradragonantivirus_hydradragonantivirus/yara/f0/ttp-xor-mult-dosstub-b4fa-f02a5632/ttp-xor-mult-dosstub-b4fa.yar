rule TTP_XOR_MULT_DOSStub_b4fa {
  strings:
    $key_b4fa = { e0 92 [2] 94 8a [2] d3 88 [2] 94 99 [2] da 95 [2] d6 9f [2] c1 94 [2] da da [2] e7 }

  condition:
    any of them
}