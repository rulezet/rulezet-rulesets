rule TTP_XOR_MULT_DOSStub_78a7 {
  strings:
    $key_78a7 = { 2c cf [2] 58 d7 [2] 1f d5 [2] 58 c4 [2] 16 c8 [2] 1a c2 [2] 0d c9 [2] 16 87 [2] 2b }

  condition:
    any of them
}