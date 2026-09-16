rule TTP_XOR_MULT_DOSStub_b2c1 {
  strings:
    $key_b2c1 = { e6 a9 [2] 92 b1 [2] d5 b3 [2] 92 a2 [2] dc ae [2] d0 a4 [2] c7 af [2] dc e1 [2] e1 }

  condition:
    any of them
}