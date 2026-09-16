rule TTP_XOR_MULT_DOSStub_6c91 {
  strings:
    $key_6c91 = { 38 f9 [2] 4c e1 [2] 0b e3 [2] 4c f2 [2] 02 fe [2] 0e f4 [2] 19 ff [2] 02 b1 [2] 3f }

  condition:
    any of them
}