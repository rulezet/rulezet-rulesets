rule TTP_XOR_MULT_DOSStub_1e90 {
  strings:
    $key_1e90 = { 4a f8 [2] 3e e0 [2] 79 e2 [2] 3e f3 [2] 70 ff [2] 7c f5 [2] 6b fe [2] 70 b0 [2] 4d }

  condition:
    any of them
}