rule TTP_XOR_MULT_DOSStub_1c96 {
  strings:
    $key_1c96 = { 48 fe [2] 3c e6 [2] 7b e4 [2] 3c f5 [2] 72 f9 [2] 7e f3 [2] 69 f8 [2] 72 b6 [2] 4f }

  condition:
    any of them
}