rule TTP_XOR_MULT_DOSStub_2b8b {
  strings:
    $key_2b8b = { 7f e3 [2] 0b fb [2] 4c f9 [2] 0b e8 [2] 45 e4 [2] 49 ee [2] 5e e5 [2] 45 ab [2] 78 }

  condition:
    any of them
}