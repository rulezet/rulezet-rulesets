rule TTP_XOR_MULT_DOSStub_3c87 {
  strings:
    $key_3c87 = { 68 ef [2] 1c f7 [2] 5b f5 [2] 1c e4 [2] 52 e8 [2] 5e e2 [2] 49 e9 [2] 52 a7 [2] 6f }

  condition:
    any of them
}