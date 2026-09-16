rule TTP_XOR_MULT_DOSStub_1890 {
  strings:
    $key_1890 = { 4c f8 [2] 38 e0 [2] 7f e2 [2] 38 f3 [2] 76 ff [2] 7a f5 [2] 6d fe [2] 76 b0 [2] 4b }

  condition:
    any of them
}