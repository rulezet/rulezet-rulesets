rule TTP_XOR_MULT_DOSStub_1a86 {
  strings:
    $key_1a86 = { 4e ee [2] 3a f6 [2] 7d f4 [2] 3a e5 [2] 74 e9 [2] 78 e3 [2] 6f e8 [2] 74 a6 [2] 49 }

  condition:
    any of them
}