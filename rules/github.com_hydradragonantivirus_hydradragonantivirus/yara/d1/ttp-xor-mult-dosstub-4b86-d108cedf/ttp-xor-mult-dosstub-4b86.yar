rule TTP_XOR_MULT_DOSStub_4b86 {
  strings:
    $key_4b86 = { 1f ee [2] 6b f6 [2] 2c f4 [2] 6b e5 [2] 25 e9 [2] 29 e3 [2] 3e e8 [2] 25 a6 [2] 18 }

  condition:
    any of them
}