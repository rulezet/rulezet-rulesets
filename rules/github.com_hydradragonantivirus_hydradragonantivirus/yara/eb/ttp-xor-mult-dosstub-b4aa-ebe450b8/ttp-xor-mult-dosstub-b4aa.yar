rule TTP_XOR_MULT_DOSStub_b4aa {
  strings:
    $key_b4aa = { e0 c2 [2] 94 da [2] d3 d8 [2] 94 c9 [2] da c5 [2] d6 cf [2] c1 c4 [2] da 8a [2] e7 }

  condition:
    any of them
}