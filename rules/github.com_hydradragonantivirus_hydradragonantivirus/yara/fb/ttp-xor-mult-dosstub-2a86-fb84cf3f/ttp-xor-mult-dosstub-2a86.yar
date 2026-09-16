rule TTP_XOR_MULT_DOSStub_2a86 {
  strings:
    $key_2a86 = { 7e ee [2] 0a f6 [2] 4d f4 [2] 0a e5 [2] 44 e9 [2] 48 e3 [2] 5f e8 [2] 44 a6 [2] 79 }

  condition:
    any of them
}