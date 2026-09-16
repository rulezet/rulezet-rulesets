rule TTP_XOR_MULT_DOSStub_b402 {
  strings:
    $key_b402 = { e0 6a [2] 94 72 [2] d3 70 [2] 94 61 [2] da 6d [2] d6 67 [2] c1 6c [2] da 22 [2] e7 }

  condition:
    any of them
}