rule TTP_XOR_MULT_DOSStub_b453 {
  strings:
    $key_b453 = { e0 3b [2] 94 23 [2] d3 21 [2] 94 30 [2] da 3c [2] d6 36 [2] c1 3d [2] da 73 [2] e7 }

  condition:
    any of them
}