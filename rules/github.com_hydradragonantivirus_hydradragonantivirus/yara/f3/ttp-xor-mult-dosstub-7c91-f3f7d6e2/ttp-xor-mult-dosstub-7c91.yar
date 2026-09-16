rule TTP_XOR_MULT_DOSStub_7c91 {
  strings:
    $key_7c91 = { 28 f9 [2] 5c e1 [2] 1b e3 [2] 5c f2 [2] 12 fe [2] 1e f4 [2] 09 ff [2] 12 b1 [2] 2f }

  condition:
    any of them
}