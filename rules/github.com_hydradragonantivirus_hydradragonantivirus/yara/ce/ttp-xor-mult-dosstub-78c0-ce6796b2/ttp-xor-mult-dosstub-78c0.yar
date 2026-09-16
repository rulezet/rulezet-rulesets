rule TTP_XOR_MULT_DOSStub_78c0 {
  strings:
    $key_78c0 = { 2c a8 [2] 58 b0 [2] 1f b2 [2] 58 a3 [2] 16 af [2] 1a a5 [2] 0d ae [2] 16 e0 [2] 2b }

  condition:
    any of them
}