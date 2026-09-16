rule TTP_XOR_MULT_DOSStub_4b87 {
  strings:
    $key_4b87 = { 1f ef [2] 6b f7 [2] 2c f5 [2] 6b e4 [2] 25 e8 [2] 29 e2 [2] 3e e9 [2] 25 a7 [2] 18 }

  condition:
    any of them
}