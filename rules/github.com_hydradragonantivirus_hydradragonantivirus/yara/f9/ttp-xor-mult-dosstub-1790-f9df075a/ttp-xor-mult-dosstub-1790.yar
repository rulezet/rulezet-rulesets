rule TTP_XOR_MULT_DOSStub_1790 {
  strings:
    $key_1790 = { 43 f8 [2] 37 e0 [2] 70 e2 [2] 37 f3 [2] 79 ff [2] 75 f5 [2] 62 fe [2] 79 b0 [2] 44 }

  condition:
    any of them
}