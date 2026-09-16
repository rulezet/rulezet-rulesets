rule TTP_XOR_MULT_DOSStub_7990 {
  strings:
    $key_7990 = { 2d f8 [2] 59 e0 [2] 1e e2 [2] 59 f3 [2] 17 ff [2] 1b f5 [2] 0c fe [2] 17 b0 [2] 2a }

  condition:
    any of them
}