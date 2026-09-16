rule TTP_XOR_MULT_DOSStub_7c87 {
  strings:
    $key_7c87 = { 28 ef [2] 5c f7 [2] 1b f5 [2] 5c e4 [2] 12 e8 [2] 1e e2 [2] 09 e9 [2] 12 a7 [2] 2f }

  condition:
    any of them
}