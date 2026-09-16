rule TTP_XOR_MULT_DOSStub_6a8b {
  strings:
    $key_6a8b = { 3e e3 [2] 4a fb [2] 0d f9 [2] 4a e8 [2] 04 e4 [2] 08 ee [2] 1f e5 [2] 04 ab [2] 39 }

  condition:
    any of them
}