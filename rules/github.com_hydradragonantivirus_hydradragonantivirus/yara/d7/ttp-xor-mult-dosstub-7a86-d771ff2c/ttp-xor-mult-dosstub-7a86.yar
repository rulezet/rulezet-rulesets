rule TTP_XOR_MULT_DOSStub_7a86 {
  strings:
    $key_7a86 = { 2e ee [2] 5a f6 [2] 1d f4 [2] 5a e5 [2] 14 e9 [2] 18 e3 [2] 0f e8 [2] 14 a6 [2] 29 }

  condition:
    any of them
}