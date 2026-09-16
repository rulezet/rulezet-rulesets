rule TTP_XOR_MULT_DOSStub_5990 {
  strings:
    $key_5990 = { 0d f8 [2] 79 e0 [2] 3e e2 [2] 79 f3 [2] 37 ff [2] 3b f5 [2] 2c fe [2] 37 b0 [2] 0a }

  condition:
    any of them
}