rule TTP_XOR_MULT_DOSStub_4a86 {
  strings:
    $key_4a86 = { 1e ee [2] 6a f6 [2] 2d f4 [2] 6a e5 [2] 24 e9 [2] 28 e3 [2] 3f e8 [2] 24 a6 [2] 19 }

  condition:
    any of them
}