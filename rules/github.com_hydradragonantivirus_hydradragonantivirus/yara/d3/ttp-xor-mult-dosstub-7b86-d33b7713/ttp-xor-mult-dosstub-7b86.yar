rule TTP_XOR_MULT_DOSStub_7b86 {
  strings:
    $key_7b86 = { 2f ee [2] 5b f6 [2] 1c f4 [2] 5b e5 [2] 15 e9 [2] 19 e3 [2] 0e e8 [2] 15 a6 [2] 28 }

  condition:
    any of them
}