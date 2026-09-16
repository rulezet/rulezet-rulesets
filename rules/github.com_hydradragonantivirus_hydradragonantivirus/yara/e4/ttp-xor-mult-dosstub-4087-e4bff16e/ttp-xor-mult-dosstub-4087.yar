rule TTP_XOR_MULT_DOSStub_4087 {
  strings:
    $key_4087 = { 14 ef [2] 60 f7 [2] 27 f5 [2] 60 e4 [2] 2e e8 [2] 22 e2 [2] 35 e9 [2] 2e a7 [2] 13 }

  condition:
    any of them
}