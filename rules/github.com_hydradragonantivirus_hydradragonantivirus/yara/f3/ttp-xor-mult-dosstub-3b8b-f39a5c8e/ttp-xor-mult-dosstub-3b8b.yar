rule TTP_XOR_MULT_DOSStub_3b8b {
  strings:
    $key_3b8b = { 6f e3 [2] 1b fb [2] 5c f9 [2] 1b e8 [2] 55 e4 [2] 59 ee [2] 4e e5 [2] 55 ab [2] 68 }

  condition:
    any of them
}