rule TTP_XOR_MULT_DOSStub_5c87 {
  strings:
    $key_5c87 = { 08 ef [2] 7c f7 [2] 3b f5 [2] 7c e4 [2] 32 e8 [2] 3e e2 [2] 29 e9 [2] 32 a7 [2] 0f }

  condition:
    any of them
}