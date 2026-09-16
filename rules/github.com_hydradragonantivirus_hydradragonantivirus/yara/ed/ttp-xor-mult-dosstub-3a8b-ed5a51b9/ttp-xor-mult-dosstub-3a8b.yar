rule TTP_XOR_MULT_DOSStub_3a8b {
  strings:
    $key_3a8b = { 6e e3 [2] 1a fb [2] 5d f9 [2] 1a e8 [2] 54 e4 [2] 58 ee [2] 4f e5 [2] 54 ab [2] 69 }

  condition:
    any of them
}