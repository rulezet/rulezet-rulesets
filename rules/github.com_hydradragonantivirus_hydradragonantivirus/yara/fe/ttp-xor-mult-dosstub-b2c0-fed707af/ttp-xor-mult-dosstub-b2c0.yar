rule TTP_XOR_MULT_DOSStub_b2c0 {
  strings:
    $key_b2c0 = { e6 a8 [2] 92 b0 [2] d5 b2 [2] 92 a3 [2] dc af [2] d0 a5 [2] c7 ae [2] dc e0 [2] e1 }

  condition:
    any of them
}