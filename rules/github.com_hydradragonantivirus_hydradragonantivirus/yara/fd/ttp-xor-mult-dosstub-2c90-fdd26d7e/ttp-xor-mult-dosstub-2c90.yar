rule TTP_XOR_MULT_DOSStub_2c90 {
  strings:
    $key_2c90 = { 78 f8 [2] 0c e0 [2] 4b e2 [2] 0c f3 [2] 42 ff [2] 4e f5 [2] 59 fe [2] 42 b0 [2] 7f }

  condition:
    any of them
}