rule TTP_XOR_MULT_DOSStub_5c80 {
  strings:
    $key_5c80 = { 08 e8 [2] 7c f0 [2] 3b f2 [2] 7c e3 [2] 32 ef [2] 3e e5 [2] 29 ee [2] 32 a0 [2] 0f }

  condition:
    any of them
}