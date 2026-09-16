rule TTP_XOR_MULT_DOSStub_1c91 {
  strings:
    $key_1c91 = { 48 f9 [2] 3c e1 [2] 7b e3 [2] 3c f2 [2] 72 fe [2] 7e f4 [2] 69 ff [2] 72 b1 [2] 4f }

  condition:
    any of them
}