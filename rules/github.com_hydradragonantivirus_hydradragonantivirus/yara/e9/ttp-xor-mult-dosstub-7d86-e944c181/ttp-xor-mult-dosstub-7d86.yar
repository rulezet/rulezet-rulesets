rule TTP_XOR_MULT_DOSStub_7d86 {
  strings:
    $key_7d86 = { 29 ee [2] 5d f6 [2] 1a f4 [2] 5d e5 [2] 13 e9 [2] 1f e3 [2] 08 e8 [2] 13 a6 [2] 2e }

  condition:
    any of them
}