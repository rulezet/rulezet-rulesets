rule TTP_XOR_MULT_DOSStub_4e87 {
  strings:
    $key_4e87 = { 1a ef [2] 6e f7 [2] 29 f5 [2] 6e e4 [2] 20 e8 [2] 2c e2 [2] 3b e9 [2] 20 a7 [2] 1d }

  condition:
    any of them
}