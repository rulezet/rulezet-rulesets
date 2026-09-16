rule TTP_XOR_MULT_DOSStub_4c90 {
  strings:
    $key_4c90 = { 18 f8 [2] 6c e0 [2] 2b e2 [2] 6c f3 [2] 22 ff [2] 2e f5 [2] 39 fe [2] 22 b0 [2] 1f }

  condition:
    any of them
}